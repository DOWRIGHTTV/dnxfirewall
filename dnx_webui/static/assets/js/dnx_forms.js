function toggleFormField(condition, idArray) {
    // set disabled field based on passed in condition. if condition is true, field is disabled.
    let field_val = !!btn.checked;

    for (let id of idArray) {
        document.getElementById(id).disabled = field_val;
    }
}
