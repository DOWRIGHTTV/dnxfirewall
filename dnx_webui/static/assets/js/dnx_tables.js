function toggleFormField(condition, idArray) {
  // set disabled field based on passed in condition. if condition is true, field is disabled.
  let field_val = !!condition;

  for (let id of idArray) {
    document.getElementById(id).disabled = field_val;
  }
}

class DNXWebuiTable {

  /* instance attributes:
  * table_class_selector: class name (base) of the table to be loaded
  * full_table_el: the full table element (including header)
  * table_el: the table element (body only)
  * colorize: boolean, whether the table is colorized (set by class selector)
  * filterable: boolean, whether the table is filterable (set by class selector)
  * movable: boolean, whether the table is movable (set by class selector)
  */

  constructor(table_class_selector = 'default-table') {

    /*
    * table_class_selector: class name of the table to be loaded
    * filterable: boolean, whether the table is filterable
    ** filter_input: the input element of the filter field
    * movable: boolean, whether the table is movable
    * colorize: boolean, whether the table is colorized
    */

    this.table_class_selector = table_class_selector;

    this.full_table_el = document.querySelector(`.${table_class_selector}`);

    this.table_el = this.full_table_el.getElementsByTagName('tbody')[0];

    this.colorize = this.full_table_el.classList.contains('colorize');
    this.filterable = this.full_table_el.classList.contains('filterable');
    this.movable = this.full_table_el.classList.contains('movable');

    this.filter_input = document.getElementById(`${this.table_class_selector}-filter`);
  }

  init() {
    if (this.colorize) {
      this.colorize_table();
    }
  }

  update_table_data(rows) {
    for (let i = 0; i < rows.length; i++) {
      let tr = this.table_el.insertRow();

      for (let ix = 0; ix < rows[i].length; ix++) {
        tr.insertCell(ix).innerHTML = rows[i][ix];
      }
    }
    // recolorize after every table update
    if (this.colorize) {
      this.colorize_table();
    }
  }

  colorize_table() {
    let table_row_array = this.table_el.getElementsByTagName('tr');

    for (let i = 0; i < table_row_array.length; i++) {
      if (i % 2 === 0) {
        table_row_array[i].className = 'tr-even';
      }
      else {
        table_row_array[i].className = 'tr-odd';
      }
    }
  }

  filter_table(n1, n2) {
    if (!this.filterable) { console.log('table not filterable'); return; }

    if (this.filter_input.value.length === 1) { return; }

    let table_row_array = table.getElementsByTagName('tr');

    for (let i = 0; i < tr.length; i++) {
      let td_list = table_row_array[i].getElementsByTagName('td');

      if (td_list.length < n2) {
        continue;
      }

      for (let f = n1; f <= n2; f++) {
        let field = td_list[f].textContent;

        if (field.indexOf(this.filter_input.value) === -1) {
          table_row_array[i].style.display = 'none';
        }
        else {
          table_row_array[i].style.display = '';
          break;
        }
      }
    }
    // recolorize after every table update
    if (this.colorize) {
      this.colorize_table();
    }
  }
}

class DNXWebuiTableFormModal extends DNXWebuiTable {
//
  initialized = false;

  init(cell_start = 0, cell_end = 99) {
    // initialize the form modal that will show up on row click (uses table class selector as base name)
    // cell start = lower bound for cells to be clickable
    // cell end = upper bound for cells to be clickable

    super.init();

    this.form_el = document.querySelector(`.${this.table_class_selector}-form`);
    this.cell_start = cell_start;
    this.cell_end = cell_end;

    this.form_el.addEventListener('click', this.click_row_handler.bind(this));

    this.initialized = true;
  }

  move_up(id) {
    // basic protection, but shouldn't be hit TODO: figure out how the id string makes this work???
    if (!this.movable) return;

    let prev = id.previousElementSibling;
    if (prev == null) return;

    id.setAttribute('class', 'ease-in');
    prev.parentNode.insertBefore(id, prev);
  }

  move_down(id) {
    // basic protection, but shouldn't be hit TODO: figure out how the id string makes this work???
    if (!this.movable) return;

    let next = id.nextElementSibling;
    if (next == null) return;

    id.setAttribute('class', 'ease-in');

    let next2 = next.nextElementSibling;
    if (next2 == null) {
      id.parentNode.append(id);
    }
    else {
      next2.parentNode.insertBefore(id, next2);
    }
  }

  click_row_handler(click) {
    if (click.target.cellIndex == null) return;
    if (click.target.cellIndex < this.cell_start || click.target.cellIndex > this.cell_end) return;

    let selected_table_row = click.target.parentNode;

    let form_modal = M.Modal.init(this.form_editor, {dismissible: false});

    // note: this method needs to be redefined in the child class since each table will have different forms
    try {
      this._update_form_from_row(selected_table_row);
    }
    catch (e) {
      console.log(e);
      return;
    }
    finally {}

    form_modal.open();
  }

  click_form_submit_handler() {
    try {
      this._update_row_from_form();
    }
    catch (e) {
      console.log(e);
    }
    finally {}
  }

  _update_form_from_row(selected_table_row) {
    console.log('fill_form() not defined in child class');
  }

  _update_row_from_form() {
    console.log('update_row_from_form() not defined in child class');
  }
}