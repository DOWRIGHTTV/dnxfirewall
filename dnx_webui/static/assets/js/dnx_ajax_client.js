class AjaxClient {
    constructor(baseUri, onErrorCallback = null) {
        this._baseUrl = baseUri;
        this._onErrorCallback = onErrorCallback;
    }

    get baseUrl() {
        return this._baseUrl;
    }

    async post(url = '', data = {}) {
        const response =
            await fetch(this.baseUrl + url, {
                method : 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            })

        if (response.ok) {
            let ajaxResponse = await response.json();

            return ajaxResponse.result;
        }
    }

   handleResponse(response, field = null) {
       if (response.error) {
           let commitError = document.querySelector("#ajax-error-modal");
           commitError.querySelector("h5").innerText = response.message;

           let errorModal = M.Modal.init(
               commitError, {
                   dismissible: false
               }
           );
           errorModal.open();

           console.log("[server/response]: ", response);

           // notifying of error so field can be reset
           return true;

       } else {
           console.log("[server/response]: successful update.");
       }
   }
}
const ajaxClient = new AjaxClient(location.pathname);
