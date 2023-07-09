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
    let full_url = this.base_url + `/${endpoint}`;
    let send_data = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }

    try {
      response = await fetch(full_url, send_data)
    }
    catch (e) {
      return null
    }

    // TODO: handle server related errors via a modal here.
    if (!response.ok) { return; }

    // note: currently all responses will be marked successful, even if the application identified an error.
    // the error code, if any, will be available in the response data.
    if (!response.success) { return; }

    let ajaxResponse = await response.json();

    if (this.debug) {
      console.log(`[server/response]: ${ajaxResponse}`,);
    }

    let response_data = ajaxResponse.result;

    if (!response_data.error) {
      if (this.onSuccessCallback) {
        this.onSuccessCallback.call(response_data);
      }
      else if (alternate_handler) {
        alternate_handler.call(response_data);
      }
      else {
        let message_popup = document.querySelector('#ajax-response-modal');
        message_popup.querySelector('h5').innerText = response_data.message;

        M.Modal.init(message_popup, {dismissible: false}).open();

        if (this.debug) {
          console.log('[server/response]: successful update.');
        }
      }

      return true;

    }
    else {
      let commitError = document.querySelector('#ajax-error-modal');
      commitError.querySelector('h5').innerText = response_data.message;

      M.Modal.init(commitError, { dismissible: false }).open();

      console.log('[server/response]: ', response);

      return false;
    }
  }
}
