
const loadTableData = (rows) => {
    const table = document.getElementById("filter-table-body");

    let colorize = table.classList.contains('colorize');

    for (let i = 0; i < rows.length; i++) {
        let tr = table.insertRow();
        if (colorize) { colorizeRow(i, tr); }
        for (let i = 0; i < rows.length; i++) {

            tr.insertCell(i).innerHTML = rows[i];
        }
    }
}
function colorizeTable() {
    const tables = document.querySelectorAll(".colorize");
    for (let table of tables) {

        let tr = table.getElementsByTagName("tr");
        for (let i = 0; i < tr.length; i++) {
            colorizeRow(i, tr)
        }
    }
}
function filterTable(n1, n2, id='') {
    let input = document.getElementById(`filter-input${id}`);
    let table = document.getElementById(`filter-table${id}`);
    let tr = table.getElementsByTagName("tr");

    let colorize = table.classList.contains('colorize');

    let r = 0;
    for (let i = 0; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName("td");

        if (td.length === 0) { continue; }

        for (let e = n1; e < n2; e++) {

            let ele = td[e];
            let txtValue = ele.textContent || ele.innerText;

            if (txtValue.toUpperCase().indexOf(input.value.toUpperCase()) > -1) {
                tr[i].style.display = ""; r++;

                if (colorize) { colorizeRow(r, tr); }
                console.log(r)
                break;

            } else {
                tr[i].style.display = "none";
            }
        }

    }
}
function colorizeRow(i, tr) {
    if (i % 2 === 0) {
        tr[i].className = "tr-even";
    } else {
        tr[i].className = "tr-odd";
    }
}
