async function updateData(table_type) {
    let response = await ajaxClient.post('/get', { table: `${table_type}` });

    if (response) {
        // this needs to be worked on to differentiate whether a page update or a new table load. if new table
        // the table body should be reset, data retained and (notify of no more data? grey out more data btn?)
        if (response.length === 0) {
            console.log('No data!')
            return;
        }

        // Data do something with it.
        // console.log(response);

        // temp conditional for resetting table data if new table is requested. otherwise, data will get appended.
        if (1) {
            document.getElementById('filter-table-body').innerHTML = '';
        }

        loadTableData(response);
    }
}
document.addEventListener('DOMContentLoaded', () => {updateData('default');})
