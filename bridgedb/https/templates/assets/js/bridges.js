// Takes one argument, `element`, which should be a string specifying the id
// of the element whose text should be selected.
function selectText(element) {
  try {
    var range;
    var selection;
    text = document.getElementById(element);

    if (document.body.createTextRange) {
      range = document.body.createTextRange();
      range.moveToElementText(text);
      range.select();
    } else if (window.getSelection) {
      selection = window.getSelection();
      range = document.createRange();
      range.selectNodeContents(text);
      selection.removeAllRanges();
      selection.addRange(range);
    }
  } catch (e) {
    console.log(e);
  }
}

function displayOrHide(element) {
  try {
    e = document.getElementById(element);
    if (e.classList.contains('hidden')) {
      // Don't use classList.toggle() because vendors seem to handle the
      // secondary, optional "force" parameter in different ways.
      document.getElementById(element).classList.remove('hidden');
      document.getElementById(element).classList.add('visible');
      document.getElementById(element).setAttribute('aria-hidden', 'false');
    } else if (e.classList.contains('visible')) {
      document.getElementById(element).classList.remove('visible');
      document.getElementById(element).classList.add('hidden');
      document.getElementById(element).setAttribute('aria-hidden', 'true');
    }
  } catch (err) {
    console.log(err);
  }
}

window.onload = function() {
  var selectBtn = document.getElementById('selectbtn');
  if (selectBtn) {
    document.getElementById('selectbtn').addEventListener('click',
      function() {
        selectText('bridgelines');
      }, false);
    // Make the 'Select All' button clickable:
    selectBtn.classList.remove('disabled');
    selectBtn.setAttribute('aria-disabled', 'false');
  }

  var bridgesContainer = document.getElementById('container-bridges');
  if (bridgesContainer) {
    document.getElementById('bridgelines').classList.add('cursor-copy');
    document.getElementById('bridgelines').addEventListener('click',
      function() {
        selectText('bridgelines');
      }, false);
  }

  var qrcodeBtn = document.getElementById('qrcodebtn');
  if (qrcodeBtn) {
    document.getElementById('qrcodebtn').addEventListener('click',
      function() {
        displayOrHide('qrcode');
      }, false);
    // Remove the href attribute that opens the QRCode image as a data: URL if
    // JS is disabled:
    document.getElementById('qrcodebtn').removeAttribute('href');
  }

  var qrModalBtn = document.getElementById('qrcode-modal-btn');
  if (qrModalBtn) {
    document.getElementById('qrcode-modal-btn').addEventListener('click',
      function() {
        displayOrHide('qrcode');
      }, false);
  }
};
