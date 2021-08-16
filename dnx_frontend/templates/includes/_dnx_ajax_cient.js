<script type="text/javascript">
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

        return await this.__handleResponse(response);
    }

    async __handleResponse(response) {
        if (response.ok) {
            let ajaxResponse = await response.json();

            if (ajaxResponse.success) {
                return ajaxResponse.result;
            }

            if (this._onErrorCallback) {
                this._onErrorCallback(ajaxResponse.error);
            }

            return null;
        }
    }
}

const ajaxClient = new AjaxClient('/{{"/".join(uri_path)}}');

$(() => {
    $('#table').on(
        'change',
        async function(e) {
            await updateData($('#table').val());
        });
})

const updateData = 
    async (table_type) => {
        let response = await ajaxClient.post('/get', { table: `${table_type}` });

        if (response) {
            if (response.length === 0) {
                console.log('No data!')
                return;
            }

            // Data do something with it.
            console.log(response);
        }
}

</script>