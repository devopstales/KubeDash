// @ts-check


/*
This function set hidden=False on elements from input array
*/
/**
 * @param {string[]} elements
 */
function unhideElementsById(elements) {
  for (let i = 0; i < elements.length; i++) {
    var x = document.getElementById(elements[i]);
    if (x) {
      if (x.hidden === true) {
          x.hidden=false;
      } else {
          x.hidden=true;
      }
    } else {
      console.log("unhideElementsById: Element X not found");
    }
  }
}

/* 
This function change object type from password to text. 
Whit this shows the content of the password element.
*/
/**
 * @param {string} element
 */
function showPasswords(element) {
  const x = document.getElementById(element);
  if (x && x instanceof HTMLInputElement) {
    if (x.type === "password" ) {
      x.type = "text";
    } else {
      x.type = "password";
    }
    const y = document.getElementById(element+"_icon");
    if (y) {
      if (y.innerHTML === "visibility_off" ) {
          y.innerHTML = "visibility"
      } else {
          y.innerHTML = "visibility_off"
      }
    }
  } else {
    console.log("getElementById: Element X not found");
  }
};

/**
 * @param {string} string
 * @returns {boolean}
 */
function isValidUrl(string) {
  try {
      new URL(string);
      return true;
  } catch (err) {
      return false;
  }
};

/**
 * @typedef {Object} ClusterFormElements
 * @property {HTMLInputElement} k8s_context
 * @property {HTMLInputElement} k8s_server_url
 * @property {HTMLInputElement} k8s_server_ca
 */

/**
 * @param {string} element
 * @returns {boolean}
 */
function validateClusterForm(element) {
  /** @type {ClusterFormElements} */
  const formElements = {
    k8s_context: document.forms[element]["k8s_context"],
    k8s_server_url: document.forms[element]["k8s_server_url"],
    k8s_server_ca: document.forms[element]["k8s_server_ca"]
  };

  let k8s_server_url_valid = false;
  let k8s_server_ca_valid = false;

  // test url
  if (isValidUrl(formElements.k8s_server_url.value)) {
    formElements.k8s_context.classList.add("is-valid");
    formElements.k8s_server_url.classList.add("is-valid");
    k8s_server_url_valid = true;
  } else {
    formElements.k8s_context.classList.add("is-valid");
    formElements.k8s_server_url.classList.add("is-invalid");
    k8s_server_url_valid = false;
  }

  k8s_server_ca_valid = true;
  // test if certificate
  // if (formElements.k8s_server_ca.value.includes("cert") || formElements.k8s_server_ca.value.includes("pem")) {
  //     formElements.k8s_server_ca.classList.add("is-valid");
  //     k8s_server_ca_valid = true;
  // } else {
  //     formElements.k8s_server_ca.classList.add("is-invalid");
  //     k8s_server_ca_valid = false;
  // }

  // finale validation
  return k8s_server_ca_valid && k8s_server_url_valid;
};

/**
 * @param {string} element
 * @returns {void}
 */

//function showSecret(element) {
//  var x = document.getElementById(element);
//  if (x) {
//    if (x.classList.contains('textshadow')) {
//        x.classList.remove("textshadow");
//    } else {
//        x.classList.add("textshadow");
//    }
//  } else {
//    console.log("unhideElementsById: Element X not found");
//  }
//
//  var y = document.getElementById(element+"_icon");
//  if (y) {
//    if (y.innerHTML === "visibility_off" ) {
//        y.innerHTML = "visibility"
//    } else {
//        y.innerHTML = "visibility_off"
//    }
//  } else {
//    console.log("unhideElementsById: Element Y not found");
//  }
//};

function showSecret(element) {
  const secretElement = document.getElementById(element);
  const iconElement = document.getElementById(`${element}_icon`);

  // Null checks (critical for production)
  if (!secretElement || !iconElement) {
      console.error(`Element with ID '${element}' or its icon not found!`);
      return; // Exit early if elements don't exist
  }

  // Toggle visibility
  secretElement.classList.toggle("textshadow");

  // Update icon
  const isHidden = secretElement.classList.contains("textshadow");
  iconElement.textContent = isHidden ? "visibility_off" : "visibility";

  // Re-highlight if visible (optional)
  //if (!isHidden) {
  //    const codeBlock = secretElement.querySelector('code');
  //    if (codeBlock) hljs.highlightElement(codeBlock);
  //}
};