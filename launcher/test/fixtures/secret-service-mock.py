#!/usr/bin/env python3
"""secret-service-mock: a minimal org.freedesktop.Secret.Service for tests.

Serves ONE collection (alias "default", always unlocked) holding the items
given on the command line, over PLAIN sessions only (the algorithm goose
1.53.0's keyring crate opens with). Enough for a `keyring` crate client
(goose's `system-keyring` feature) to search, read, create and delete an
item. Every method call is appended to the log file, one line each, so a
test can tell whether a client reached the service at all.

    secret-service-mock.py <bus address> <log file> [<attrs-json> <secret>]...

Needs dbus-python and PyGObject (python3-dbus, python3-gi); the tests that
use it self-SKIP without them. Test fixture only: Mandu-new.
"""
import json
import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

SERVICE_IFACE = "org.freedesktop.Secret.Service"
COLLECTION_IFACE = "org.freedesktop.Secret.Collection"
ITEM_IFACE = "org.freedesktop.Secret.Item"
SESSION_IFACE = "org.freedesktop.Secret.Session"
PROPS_IFACE = "org.freedesktop.DBus.Properties"
ROOT = "/org/freedesktop/secrets"
COLLECTION_PATH = ROOT + "/collection/login"

LOG = None


def log(line):
    with open(LOG, "a", encoding="utf8") as f:
        f.write(line + "\n")


class NotSupported(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.NotSupported"


class NoSuchObject(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.Secret.Error.NoSuchObject"


class Props(dbus.service.Object):
    def props(self):
        return {}

    @dbus.service.method(PROPS_IFACE, in_signature="ss", out_signature="v")
    def Get(self, iface, name):
        log(f"Properties.Get {self.__dbus_object_path__} {name}")
        p = self.props()
        if name not in p:
            raise NoSuchObject(name)
        return p[name]

    @dbus.service.method(PROPS_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        log(f"Properties.GetAll {self.__dbus_object_path__}")
        return self.props()

    @dbus.service.method(PROPS_IFACE, in_signature="ssv")
    def Set(self, iface, name, value):
        log(f"Properties.Set {self.__dbus_object_path__} {name}")


class Session(dbus.service.Object):
    @dbus.service.method(SESSION_IFACE)
    def Close(self):
        log("Session.Close")
        self.remove_from_connection()


class Item(Props):
    def __init__(self, store, path, attrs, secret, label):
        super().__init__(store.conn, path)
        self.store, self.path, self.attrs, self.secret, self.label = store, path, dict(attrs), bytes(secret), label

    def props(self):
        return {
            "Locked": dbus.Boolean(False),
            "Attributes": dbus.Dictionary(self.attrs, signature="ss"),
            "Label": dbus.String(self.label),
            "Created": dbus.UInt64(0),
            "Modified": dbus.UInt64(0),
        }

    @dbus.service.method(ITEM_IFACE, in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session):
        log(f"Item.GetSecret {self.path}")
        return (session, dbus.ByteArray(b""), dbus.ByteArray(self.secret), "text/plain")

    @dbus.service.method(ITEM_IFACE, in_signature="(oayays)")
    def SetSecret(self, secret):
        log(f"Item.SetSecret {self.path}")
        self.secret = bytes(secret[2])

    @dbus.service.method(ITEM_IFACE, out_signature="o")
    def Delete(self):
        log(f"Item.Delete {self.path}")
        self.store.items.remove(self)
        self.remove_from_connection()
        return dbus.ObjectPath("/")


class Store:
    def __init__(self, conn):
        self.conn, self.items, self.n = conn, [], 0

    def add(self, attrs, secret, label="item"):
        self.n += 1
        item = Item(self, f"{COLLECTION_PATH}/{self.n}", attrs, secret, label)
        self.items.append(item)
        return item

    def search(self, attrs):
        return [dbus.ObjectPath(i.path) for i in self.items if all(i.attrs.get(k) == v for k, v in attrs.items())]


class Collection(Props):
    def __init__(self, store):
        super().__init__(store.conn, COLLECTION_PATH)
        self.store = store

    def props(self):
        return {
            "Items": dbus.Array([dbus.ObjectPath(i.path) for i in self.store.items], signature="o"),
            "Label": dbus.String("Login"),
            "Locked": dbus.Boolean(False),
            "Created": dbus.UInt64(0),
            "Modified": dbus.UInt64(0),
        }

    @dbus.service.method(COLLECTION_IFACE, in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        log(f"Collection.SearchItems {json.dumps(dict(attrs), sort_keys=True)}")
        return dbus.Array(self.store.search(dict(attrs)), signature="o")

    @dbus.service.method(COLLECTION_IFACE, in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        attrs = dict(props.get("org.freedesktop.Secret.Item.Attributes", {}))
        log(f"Collection.CreateItem {json.dumps(attrs, sort_keys=True)}")
        if replace:
            for i in [i for i in self.store.items if i.attrs == attrs]:
                i.secret = bytes(secret[2])
                return (dbus.ObjectPath(i.path), dbus.ObjectPath("/"))
        item = self.store.add(attrs, bytes(secret[2]), str(props.get("org.freedesktop.Secret.Item.Label", "item")))
        return (dbus.ObjectPath(item.path), dbus.ObjectPath("/"))


class Service(Props):
    def __init__(self, store):
        super().__init__(store.conn, ROOT)
        self.store, self.sessions = store, 0

    def props(self):
        return {"Collections": dbus.Array([dbus.ObjectPath(COLLECTION_PATH)], signature="o")}

    @dbus.service.method(SERVICE_IFACE, in_signature="sv", out_signature="vo")
    def OpenSession(self, algorithm, _input):
        log(f"Service.OpenSession {algorithm}")
        if algorithm != "plain":
            raise NotSupported(f"algorithm {algorithm} is not supported by the mock")
        self.sessions += 1
        path = f"{ROOT}/session/s{self.sessions}"
        Session(self.store.conn, path)
        return (dbus.String("", variant_level=1), dbus.ObjectPath(path))

    @dbus.service.method(SERVICE_IFACE, in_signature="a{ss}", out_signature="aoao")
    def SearchItems(self, attrs):
        log(f"Service.SearchItems {json.dumps(dict(attrs), sort_keys=True)}")
        return (dbus.Array(self.store.search(dict(attrs)), signature="o"), dbus.Array([], signature="o"))

    @dbus.service.method(SERVICE_IFACE, in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        log("Service.Unlock")
        return (dbus.Array(objects, signature="o"), dbus.ObjectPath("/"))

    @dbus.service.method(SERVICE_IFACE, in_signature="ao", out_signature="aoo")
    def Lock(self, objects):
        log("Service.Lock")
        return (dbus.Array([], signature="o"), dbus.ObjectPath("/"))

    @dbus.service.method(SERVICE_IFACE, in_signature="aoo", out_signature="a{o(oayays)}")
    def GetSecrets(self, items, session):
        log("Service.GetSecrets")
        out = {}
        for i in self.store.items:
            if dbus.ObjectPath(i.path) in items:
                out[dbus.ObjectPath(i.path)] = (session, dbus.ByteArray(b""), dbus.ByteArray(i.secret), "text/plain")
        return dbus.Dictionary(out, signature="o(oayays)")

    @dbus.service.method(SERVICE_IFACE, in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        log(f"Service.ReadAlias {name}")
        return dbus.ObjectPath(COLLECTION_PATH if name == "default" else "/")

    @dbus.service.method(SERVICE_IFACE, in_signature="a{sv}s", out_signature="oo")
    def CreateCollection(self, props, alias):
        log("Service.CreateCollection")
        return (dbus.ObjectPath(COLLECTION_PATH), dbus.ObjectPath("/"))


def main():
    global LOG
    address, LOG = sys.argv[1], sys.argv[2]
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    conn = dbus.bus.BusConnection(address)
    store = Store(conn)
    Service(store)
    Collection(store)
    rest = sys.argv[3:]
    for k in range(0, len(rest) - 1, 2):
        store.add(json.loads(rest[k]), rest[k + 1].encode("utf8"))
    # Kept referenced: a collected BusName releases the name.
    name = dbus.service.BusName("org.freedesktop.secrets", conn)
    log(f"ready {name.get_name()}")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
