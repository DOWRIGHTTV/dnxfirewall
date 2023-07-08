class AjaxClient {
  constructor(baseUri, onSuccessCallback = null, onErrorCallback = null, debug = false) {
    this._baseUrl = baseUri;
    this._onSuccessCallback = onSuccessCallback;
    this._onErrorCallback = onErrorCallback;

    this.debug = debug;
  }

  get baseUrl() {
    return this._baseUrl;
  }

  get onSuccessCallback() {
    return this._onSuccessCallback;
  }

  get onErrorCallback() {
    return this._onErrorCallback;
  }

  async post(endpoint= '', data= {}, alternate_handler = null) {

    let response;
    let fullUrl = this.baseUrl + `/${endpoint}`;
    let sendData = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }

    try {
      response = await fetch(fullUrl, sendData)
    }
    catch (e) {
      return null
    }

    if (response.ok) {
      let ajaxResponse = await response.json();

      if (this.onSuccessCallback) {
        this.onSuccessCallback.call(ajaxResponse);
      }
      else if (alternate_handler) {
        alternate_handler.call(ajaxResponse);
      }
      else {
        let message_popup = document.querySelector('#ajax-response-modal');
        message_popup.querySelector('h5').innerText = response.message;

        M.Modal.init(message_popup, {dismissible: false}).open();

        if (this.debug) {
          console.log('[server/response]: successful update.');
        }
      }

      return true;

    }
    else {
      let commitError = document.querySelector('#ajax-error-modal');
      commitError.querySelector('h5').innerText = response.message;

      M.Modal.init(commitError, { dismissible: false }).open();

      console.log('[server/response]: ', response);

      return false;
    }
  }
}
