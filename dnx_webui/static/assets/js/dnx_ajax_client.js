class AjaxClient {
    constructor(baseUri, onSuccessCallback = null, onErrorCallback = null) {
        this._baseUrl = baseUri;
        this._onSuccessCallback = onSuccessCallback;
        this._onErrorCallback = onErrorCallback;
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

    async post(url = '', data = {}) {

        let response;
        let fullUrl = this.baseUrl + url
        let sendData = {
            method : 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        }

        try {
            response = await fetch(fullUrl, sendData)
        } catch (e) {
            return null
        }

        if (response.ok) {
            let ajaxResponse = await response.json();

            if (this.onSuccessCallback) {
                this.onSuccessCallback.call(ajaxResponse);
            }

            return ajaxResponse.result;
        }
    }

   handleResponse(response, field = null) {
       if (response.error) {
           let commitError = document.querySelector('#ajax-error-modal');
           commitError.querySelector('h5').innerText = response.message;

           let errorModal = M.Modal.init(
               commitError, {
                   dismissible: false
               }
           );
           errorModal.open();

           console.log('[server/response]: ', response);

           // notifying of error so field can be reset
           return true;

       } else {
           console.log('[server/response]: successful update.');
       }
   }
}
