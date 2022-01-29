
const loadTableData = (items) => {
    const table = document.getElementById("filter-table-body");
    items.forEach( item => {
        let row = table.insertRow();
        for (let i = 0; i < item.length; i++) {

            let col = row.insertCell(i);
            col.innerHTML = item[i];
        }
    });

    // this should be able to be integrated into the load table data, but for now it is done
    // after the fact.
    colorizeTable();

}

function colorizeTable(id='') {
    var table = document.getElementById(`filter-table${id}`);
    var tr = table.getElementsByTagName("tr");

    for (let i = 0; i < tr.length; i++) {

        if (i % 2 === 0) {
            tr[i].className = "tr-even";
        } else {
            tr[i].className = "tr-odd";
        }
    }
}

function filterTable(n1, n2, id='') {
    var input = document.getElementById(`filter-input${id}`);
    var filter = input.value.toUpperCase();
    var table = document.getElementById(`filter-table${id}`);
    var tr = table.getElementsByTagName("tr");

    let r = 1
    for (let i = 0; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName("td");

        if (td.length === 0) { continue; }

        if (r % 2 === 0) {
            tr[i].className = "tr-even";
        } else {
            tr[i].className = "tr-odd";
        }

        for (let e = n1; e < n2; e++) {

            let ele = td[e]
            let txtValue = ele.textContent || ele.innerText;

            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                tr[i].style.display = ""; r++; break;

            } else {
                tr[i].style.display = "none";
            }

        }
    }
}
