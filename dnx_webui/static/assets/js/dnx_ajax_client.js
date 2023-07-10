class AjaxClient {
  constructor(base_uri, onSuccessCallback, onErrorCallback, debug = false) {
    this.base_url = base_uri;
    this.onSuccessCallback = onSuccessCallback;
    this.onErrorCallback = onErrorCallback;

    this.debug = debug;

    // setting response modal element attribute and initializing the modal
    this._response_modal_el = document.querySelector('#ajax-response-modal');
    M.Modal.init(this._response_modal_el, {dismissible: false});

    if (debug) {
      console.log(
        `ajax client initialized -> 
        base_url: ${this.base_url}, 
        onSuccessCallback: ${this.onSuccessCallback}, 
        onErrorCallback: ${this.onErrorCallback}`);
    }
  }

  async post(endpoint = '', data = {}, alternate_handler = null) {

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
      response = await fetch(full_url, send_data);
    }
    catch (e) {
      return null
    }

    // TODO: handle server related errors via a modal here.
    if (!response.ok) {
      return;
    }

    let response_as_json = await response.json();

    if (this.debug) {
      console.log(`[server/response]: ${JSON.stringify(response_as_json)}`);
    }

    // note: currently all responses will be marked successful, even if the application identified an error.
    // the error code, if any, will be available in the response data.
    if (!response_as_json.success) {
      return;
    }

    let response_data = response_as_json.result;

    if (!response_data.error) {
      if (this.onSuccessCallback) {
        this.onSuccessCallback.call(this, response_data);
      }
      else if (alternate_handler) {
        alternate_handler.call(this, response_data);
      }
      else {
        if (this.debug) { console.log('[server/response][success]: server successfully processed the request.'); }

        this._show_response_modal(response_data.message);
      }

      return true;

    }
    else {
      if (this.debug) { console.log('[server/response][error]: ', response_data.message); }

      this._show_response_modal(response_data.message);

      return false;
    }
  }

  _show_response_modal(message) {
    this._response_modal_el.querySelector('h5').innerText = message;

    M.Modal.getInstance(this._response_modal_el).open();
  }
}
