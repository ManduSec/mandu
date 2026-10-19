/* theme-early.js — the stored Appearance before the first paint
   (dashboard.md §4.25 Settings › Appearance, §4.25k). A CLASSIC script in
   <head>, before the stylesheets: home.js is a module and runs after the
   first paint, so a stored Dark applied from it would paint light first.
   Keep it tiny, never a module, never defer or async. Same key and values as
   the developer view's Appearance row: 'light' / 'dark' pin data-theme on
   <html>; 'system', anything else and a storage that throws leave it bare. */
(function () {
  var t = null;
  try { t = localStorage.getItem('mandu.theme'); } catch (e) { /* private window */ }
  if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
}());
