// Browse filters apply immediately: any checkbox/radio change in the filter
// panel resubmits the GET form (CSP-safe: no inline handlers).
(function () {
  "use strict";
  var form = document.getElementById("filter-form");
  if (!form) return;
  form.addEventListener("change", function (ev) {
    var t = ev.target;
    if (t && (t.type === "checkbox" || t.type === "radio")) {
      form.submit();
    }
  });
})();
