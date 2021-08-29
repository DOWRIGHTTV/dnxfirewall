<script>
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

const updateData =
    async (table_type) => {
        let response = await ajaxClient.post('/get', { table: `${table_type}` });

        if (response) {
            // this needs to be worked on to differenciate whether a page update or a new table load. if new table
            // the table body should be reset, data retained and (notify of no more data? grey out more data btn?)
            if (response.length === 0) {
                console.log('No data!')
                return;
            }

            // Data do something with it.
            // console.log(response);

            // temp conditional for resetting table data if new table is requsted. otherwise data will get appended.
            if (1) {
                document.getElementById('filter-table-body').innerHTML = '';
            }

            loadTableData(response);
        }
}
</script>
