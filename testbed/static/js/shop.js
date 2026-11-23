// Small progressive enhancement: allow alerts to be dismissed.
document.querySelectorAll(".alert").forEach(function (alert) {
  var btn = document.createElement("button");
  btn.type = "button";
  btn.className = "close";
  btn.setAttribute("aria-label", "Dismiss");
  btn.textContent = "×";
  btn.addEventListener("click", function () { alert.remove(); });
  alert.prepend(btn);
});
