'use strict';

var DashboardPage = require('./dashboard-view');
var StartProcessPage = require('./start-process');
var TaskListPage = require('./tasklist/task-list');
var TaskListSearchPage = require('./tasklist/task-search');
var CurrentTaskPage = require('./taskview/current-task');
var FormTabPage = require('./taskview/tabs/form-tab');
var HistoryTabPage = require('./taskview/tabs/history-tab');
var DiagramTabPage = require('./taskview/tabs/diagram-tab');
var DescriptionTabPage = require('./taskview/tabs/description-tab');
var TaskFiltersPage = require('./filter/task-filters');
var CreateFilterPage = require('./filter/create-filter');
var EditFilterPage = require('./filter/edit-filter');
var DeleteFilterPage = require('./filter/delete-filter');
var InvoiceStartFormPage = require('./forms/invoice-start-form');
var GenericStartFormPage = require('./forms/generic-start-form');
var AuthenticationPage = require('../../../commons/pages/authentication');

module.exports = new DashboardPage();
module.exports.taskFilters = new TaskFiltersPage();
module.exports.taskFilters.createFilterPage = new CreateFilterPage();
module.exports.taskFilters.editFilterPage = new EditFilterPage();
module.exports.taskFilters.deleteFilterPage = new DeleteFilterPage();
module.exports.taskList = new TaskListPage();
module.exports.taskList.taskSearch = new TaskListSearchPage();
module.exports.currentTask = new CurrentTaskPage();
module.exports.currentTask.form = new FormTabPage();
module.exports.currentTask.history = new HistoryTabPage();
module.exports.currentTask.diagram = new DiagramTabPage();
module.exports.currentTask.description = new DescriptionTabPage();
module.exports.currentTask.invoiceStartForm = new InvoiceStartFormPage();
module.exports.startProcess = new StartProcessPage();
module.exports.startProcess.invoiceStartForm = new InvoiceStartFormPage();
module.exports.startProcess.genericStartForm = new GenericStartFormPage();
module.exports.authentication = new AuthenticationPage();
