function toggleFormField(btn, idArray) {

    let field_val = !!btn.checked ? "" : "true";

    for (let id of idArray) {
        document.getElementById(id).disabled = field_val;
    }
}
