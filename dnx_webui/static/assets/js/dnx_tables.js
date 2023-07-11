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

  constructor(table_class_selector = 'default-table', debug = false) {

    /*
    * table_class_selector: class name of the table to be loaded
    * debug: shows verbose console output
    * filterable: boolean, whether the table is filterable
    * movable: boolean, whether the table is movable
    * colorize: boolean, whether the table is colorized
    */

    // args
    this.table_class_selector = table_class_selector;
    this.debug = debug;

    // auto generated attributes
    this.full_table_el = document.querySelector(`.${table_class_selector}`);

    if (debug) { console.log(this.full_table_el); }

    this.table_el = this.full_table_el.querySelector(`.${table_class_selector}-body`);

    this.filterable = this.full_table_el.classList.contains('filterable');
    this.movable = this.full_table_el.classList.contains('movable');

    // handling colorization in constructor i guess
    this.colorize = this.full_table_el.classList.contains('colorize');
    if (this.colorize) {
      this.colorize_table();
    }
  }

  initialize_filter(filter_min_length = 0, filter_col_start = 0, filter_col_end = 99) {
    /*
    ** _filter_input: the input element of the filter field
    ** _filter_min_length: minimum length of the filter string
    ** _filter_col_start: lower bound for cells to be clickable
    ** _filter_col_end: upper bound for cells to be clickable
    */
    if (this.filterable) {
      this._filter_input = document.getElementById(`${this.table_class_selector}-filter`)
      this._filter_min_length = filter_min_length;
      this._filter_col_start = filter_col_start;
      this._filter_col_end = filter_col_end;
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

  update_title(title_str) {
    document.querySelector(`.${this.table_class_selector}-title`).innerHTML = title_str;
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

  filter_table() {
    if (!this.filterable) { console.log('table not filterable'); return; }

    if (this._filter_input.value.length < this._filter_min_length) {
      if (this.debug) {
        console.log(`filter input length (${this._filter_input.value.length}) is less than set minimum (${this._filter_min_length})`)
      }
      return;
    }

    let table_row_array = this.table_el.getElementsByTagName('tr');

    for (let i = 0; i < table_row_array.length; i++) {
      let td_list = table_row_array[i].getElementsByTagName('td');

      // do not run filter if there are less than 4 rows. note: this can be changed later to be dynamic or user set
      if (td_list.length <= 3) {
        continue;
      }

      for (let f = this._filter_col_start; f <= this._filter_col_end; f++) {
        let field = td_list[f].textContent;

        if (field.indexOf(this._filter_input.value) === -1) {
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
  move_up(id) {
    // basic protection, but shouldn't be hit TODO: figure out how the id string makes this work???
    if (!this.movable) { return; }

    let prev = id.previousElementSibling;
    if (prev == null) { return; }

    id.setAttribute('class', 'ease-in');
    prev.parentNode.insertBefore(id, prev);
  }

  move_down(id) {
    // basic protection, but shouldn't be hit TODO: figure out how the id string makes this work???
    if (!this.movable) { return; }

    let next = id.nextElementSibling;
    if (next == null) { return; }

    id.setAttribute('class', 'ease-in');

    let next2 = next.nextElementSibling;
    if (next2 == null) {
      id.parentNode.append(id);
    }
    else {
      next2.parentNode.insertBefore(id, next2);
    }
  }
}

class DNXWebuiTableFormModal extends DNXWebuiTable {
//
  form_initialized = false;

  initialize_form(click_col_start = 0, click_col_end = 99) {
    // initialize the form modal that will show up on row click (uses table class selector as base name)

    // TODO: add code to change pointer for the specified columns
    this._click_col_start = click_col_start;
    this._click_col_end = click_col_end;

    this.table_el.addEventListener('click', this._click_row_handler.bind(this));

    this.form_el = document.querySelector(`.${this.table_class_selector}-form`);
    this.form_el.querySelector(`.${this.table_class_selector}-form-submit`).addEventListener('click', this._click_form_submit_handler.bind(this))

    this.form_initialized = true;
  }

  register_buttons(btn_selector_array) {
    // set onclick listener for buttons that are outside the table itself, but interact with the table in some way.

    for (let btn_selector of btn_selector_array) {
      let btn = document.querySelector(`.${this.table_class_selector}-btn-${btn_selector}`)

      btn.addEventListener('click', this._click_button_handler.bind(this, btn_selector));

      if (this.debug) { console.log(`${this.table_class_selector} button registered: ${btn_selector}`); }
    }

    this._register_buttons_hook();
  }

  enable_button(btn_el) {
    if (btn_el.classList.contains('btn-disabled')) {
      btn_el.classList.remove('btn-disabled');
    }
  }
  disable_button(btn_el) {
    if (!btn_el.classList.contains('btn-disabled')) {
      btn_el.classList.add('btn-disabled');
    }
  }

  _click_row_handler(click) {

    if (click.target.cellIndex == null) return;

    if (this.debug) { console.log('clicked cell index: ', click.target.cellIndex); }

    if (click.target.cellIndex < this._click_col_start || click.target.cellIndex > this._click_col_end) return;

    let selected_table_row = click.target.parentNode;

    if (this.debug) { console.log('clicked row: ', selected_table_row); }

    try {
      this._update_form_from_row(selected_table_row);
    }
    catch (e) {
      console.log(e);
      return;
    }
    finally {}

    M.Modal.init(this.form_el, {dismissible: false}).open();
  }

  _click_form_submit_handler() {
    try {
      this._update_row_from_form();
    }
    catch (e) {
      console.log(e);
    }
    finally {}
  }

  _update_form_from_row(selected_table_row) {
    console.log('_update_form_from_row() not defined in child class');
  }

  _update_row_from_form() {
    console.log('_update_row_from_form() not defined in child class');
  }

  _click_button_handler(btn_selector) {
    console.log('_click_button_handler() not defined in child class');
  }

  // hook for child class to use for additional button registration setup if needed
  _register_buttons_hook() {}
}