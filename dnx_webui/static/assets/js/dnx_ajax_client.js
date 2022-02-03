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

//        return await this.__handleResponse(response);
    }

//    async __handleResponse(response) {
//        if (response.ok) {
//            let ajaxResponse = await response.json();


//            console.log(ajaxResponse)
//            if (ajaxResponse.success) {
//                return ajaxResponse.result;
//            }

//            if (this._onErrorCallback) {
//                this._onErrorCallback(ajaxResponse.error);
//            }

//            return null;
//        }
//    }
}
const ajaxClient = new AjaxClient(location.pathname);
