class AjaxClient {
  constructor(base_uri, onSuccessCallback = null, onErrorCallback = null, debug = false) {
    this.base_url = base_uri;
    this.onSuccessCallback = onSuccessCallback;
    this.onErrorCallback = onErrorCallback;

    this.debug = debug;

    if (debug) {
      console.log(
        `ajax client initialized -> 
        base_url: ${this.base_url}, 
        onSuccessCallback: ${this.onSuccessCallback}, 
        onErrorCallback: ${this.onErrorCallback}`);
    }
  }

  //get baseUrl() {
  //  return this._baseUrl;
  //}

  //get onSuccessCallback() {
  //  return this._onSuccessCallback;
  //}
  //
  //get onErrorCallback() {
  //  return this._onErrorCallback;
  //}

  async post(endpoint= '', data= {}, alternate_handler = null) {

    let response;
    let fullUrl = this.base_url + `/${endpoint}`;
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

      if (this.debug) {
        console.log('[server/response]: ', ajaxResponse);
      }

      if (this.onSuccessCallback) {
        this.onSuccessCallback.call(ajaxResponse.result);
      }
      else if (alternate_handler) {
        alternate_handler.call(ajaxResponse.result);
      }
      else {
        let message_popup = document.querySelector('#ajax-response-modal');
        message_popup.querySelector('h5').innerText = response.result.message;

        M.Modal.init(message_popup, {dismissible: false}).open();

        if (this.debug) {
          console.log('[server/response]: successful update.');
        }
      }

      return true;

    }
    else {
      let commitError = document.querySelector('#ajax-error-modal');
      commitError.querySelector('h5').innerText = response.result.message;

      M.Modal.init(commitError, { dismissible: false }).open();

      console.log('[server/response]: ', response);

      return false;
    }
  }
}
