(function() {
  var spinner         = document.getElementById('spinner');
  var k8s_type        = spinner.getAttribute('k8s_type')
  var csrf_token      = spinner.getAttribute('csrf_token')
  var selected        = spinner.getAttribute('selected')
  var namespace       = spinner.getAttribute('namespace')
  var reply_decrement = function()
  {
    var counter     = spinner.getAttribute('value')
    var nextCounter = ( counter > 0) ? --counter : counter;
    spinner.setAttribute('value', nextCounter)

    post('/'+k8s_type+'/scale', {
      csrf_token: csrf_token,
      ns_select: namespace,
      selected: selected,
      replica_number: nextCounter,
    });
  }
  var reply_increment = function()
  {
    var counter     = spinner.getAttribute('value')
    var nextCounter = ( counter < 999) ? ++counter : counter;
    spinner.setAttribute('value', nextCounter)

    post('/'+k8s_type+'/scale', {
      csrf_token: csrf_token,
      ns_select: namespace,
      selected: selected,
      replica_number: nextCounter,
    });
  }
  document.getElementById('ctrl__button--decrement').onclick = reply_decrement;
  document.getElementById('ctrl__button--increment').onclick = reply_increment;
  })();

function post(path, params, method='post') {

  // The rest of this code assumes you are not using a library.
  // It can be made less verbose if you use one.
  const form = document.createElement('form');
  form.method = method;
  form.action = path;

  for (const key in params) {
    if (params.hasOwnProperty(key)) {
      const hiddenField = document.createElement('input');
      hiddenField.type = 'hidden';
      hiddenField.name = key;
      hiddenField.value = params[key];

      form.appendChild(hiddenField);
    }
  }
  
    document.body.appendChild(form);
    form.submit();
  }