let forms = document.querySelector('.php-email-form');

forms.addEventListener('submit', function (event) {
  event.preventDefault();

  let thisForm = this;

  thisForm.querySelector('.loading').classList.add('d-block');
  thisForm.querySelector('.error-message').classList.remove('d-block');
  thisForm.querySelector('.sent-message').classList.remove('d-block');

  let formData = new FormData(thisForm);
  formData.append('streamOrAppName', 'CloudlessPay');

  let action = "/docs/contact";

  if (!formData.get('name') || !formData.get('emailID') || !formData.get('subjectStr') || !formData.get('messageStr') || !formData.get('phoneNumber')) {
    displayError(thisForm, "Please fill in all fields.");
    return;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(formData.get('emailID'))) {
    displayError(thisForm, "Please enter a valid email address.");
    return;
  }

  const phoneRegex = /^\+?\d{1,3}?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}$/;
  if (!phoneRegex.test(formData.get('phoneNumber'))) {
    displayError(thisForm, "Please enter a valid phone number.");
    return;
  }

  php_email_form_submit(thisForm, action, formData);
});

function php_email_form_submit(thisForm, action, formData) {
  fetch(action, {
    method: 'POST',
    body: formData,
  })
    .then(response => {
      if (response.ok) {
        return response.json();
      } else {
        throw new Error(`${response.status} ${response.statusText}`);
      }
    })
    .then(data => {
      thisForm.querySelector('.loading').classList.remove('d-block');
      if (data.status === 'success') {
        thisForm.querySelector('.sent-message').classList.add('d-block');
        thisForm.reset();
      } else {
        throw new Error(data.message || "An error occurred.");
      }
    })
    .catch(error => {
      displayError(thisForm, error.message);
    });
}

function displayError(thisForm, error) {
  thisForm.querySelector('.loading').classList.remove('d-block');
  thisForm.querySelector('.error-message').innerHTML = error;
  thisForm.querySelector('.error-message').classList.add('d-block');
}
