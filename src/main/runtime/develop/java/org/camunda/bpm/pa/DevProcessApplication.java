package org.camunda.bpm.pa;

import static org.camunda.bpm.engine.variable.Variables.createVariables;
import static org.camunda.bpm.engine.variable.Variables.fileValue;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.camunda.bpm.admin.impl.web.SetupResource;
import org.camunda.bpm.application.PostDeploy;
import org.camunda.bpm.application.ProcessApplication;
import org.camunda.bpm.application.impl.ServletProcessApplication;
import org.camunda.bpm.engine.CaseService;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.RuntimeService;
import org.camunda.bpm.engine.TaskService;
import org.camunda.bpm.engine.authorization.Groups;
import org.camunda.bpm.engine.impl.ProcessEngineImpl;
import org.camunda.bpm.engine.impl.util.ClockUtil;
import org.camunda.bpm.engine.impl.util.IoUtil;
import org.camunda.bpm.engine.rest.dto.identity.UserCredentialsDto;
import org.camunda.bpm.engine.rest.dto.identity.UserDto;
import org.camunda.bpm.engine.rest.dto.identity.UserProfileDto;
import org.camunda.bpm.engine.runtime.CaseExecutionQuery;
import org.camunda.bpm.engine.runtime.ProcessInstance;
import org.camunda.bpm.engine.task.Task;
import org.camunda.bpm.model.bpmn.Bpmn;
import org.camunda.bpm.model.bpmn.BpmnModelInstance;
import org.camunda.bpm.pa.demo.InvoiceDemoDataGenerator;
import org.joda.time.DateTime;

/**
 *
 * @author nico.rehwaldt
 */
@ProcessApplication("camunda-test-processes")
public class DevProcessApplication extends ServletProcessApplication {

  private final static Logger LOGGER = Logger.getLogger(DevProcessApplication.class.getName());

  @PostDeploy
  public void startProcesses(ProcessEngine engine) throws Exception {
    createAdminDemoData(engine);
    createTasklistDemoData(engine);
    createReportDemoData(engine);
    createCockpitDemoData(engine);
  }

  private void createCockpitDemoData(final ProcessEngine engine) throws Exception {
    RuntimeService runtimeService = engine.getRuntimeService();

    Map<String, Object> vars1 = new HashMap<String, Object>();
    vars1.put("booleanVar", true);
    runtimeService.startProcessInstanceByKey("ProcessWithExclusiveGateway", "secondUserTask", vars1);

    Map<String, Object> vars2 = new HashMap<String, Object>();
    vars2.put("booleanVar", false);
    runtimeService.startProcessInstanceByKey("ProcessWithExclusiveGateway", "firstUserTask", vars2);

    runtimeService.startProcessInstanceByKey("multipleFailingServiceTasks", "aBusinessKey");

    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingDifferentProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingDifferentProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingDifferentProcess");

    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingSameProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingSameProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingSameProcess");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("TwoParallelCallActivitiesCallingSameProcess");

    runtimeService.startProcessInstanceByKey("CallingCallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("CallingCallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("CallingCallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("CallingCallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(8));
    runtimeService.startProcessInstanceByKey("CallingCallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(10));
    runtimeService.startProcessInstanceByKey("CallingCallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(12));
    runtimeService.startProcessInstanceByKey("CallingCallActivity");

    runtimeService.startProcessInstanceByKey("OrderProcess");
    runtimeService.startProcessInstanceByKey("FailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("FailingProcess");
    runtimeService.startProcessInstanceByKey("CallActivity");
    runtimeService.startProcessInstanceByKey("FailingErrorMessage");


    runtimeService.startProcessInstanceByKey("OrderProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("OrderProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("OrderProcess");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("OrderProcess");

    runtimeService.startProcessInstanceByKey("FailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("FailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("FailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("FailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(8));
    runtimeService.startProcessInstanceByKey("FailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(10));
    runtimeService.startProcessInstanceByKey("FailingProcess");

    runtimeService.startProcessInstanceByKey("FailingSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("FailingSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));

    runtimeService.startProcessInstanceByKey("AnotherFailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("AnotherFailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("AnotherFailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("AnotherFailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(8));
    runtimeService.startProcessInstanceByKey("AnotherFailingProcess");
    ClockUtil.setCurrentTime(createArtificalDate(10));
    runtimeService.startProcessInstanceByKey("AnotherFailingProcess");

    runtimeService.startProcessInstanceByKey("CallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("CallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("CallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("CallActivity");
    ClockUtil.setCurrentTime(createArtificalDate(8));
    runtimeService.startProcessInstanceByKey("CallActivity");

    Map<String, Object> params = new HashMap<String, Object>();
    params.put("value1", "a");
    params.put("value2", "b");
    params.put("value3", "c");

    runtimeService.startProcessInstanceByKey("cornercasesProcess", params);
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("cornercasesProcess", params);
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("cornercasesProcess", params);
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("cornercasesProcess", params);

    runtimeService.startProcessInstanceByKey("processWithSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("processWithSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("processWithSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("processWithSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(8));
    runtimeService.startProcessInstanceByKey("processWithSubProcess");
    ClockUtil.setCurrentTime(createArtificalDate(10));
    runtimeService.startProcessInstanceByKey("processWithSubProcess");

    runtimeService.startProcessInstanceByKey("executionProcess");
    ClockUtil.setCurrentTime(createArtificalDate(2));
    runtimeService.startProcessInstanceByKey("executionProcess");
    ClockUtil.setCurrentTime(createArtificalDate(4));
    runtimeService.startProcessInstanceByKey("executionProcess");
    ClockUtil.setCurrentTime(createArtificalDate(6));
    runtimeService.startProcessInstanceByKey("executionProcess");
    ClockUtil.setCurrentTime(createArtificalDate(8));
    runtimeService.startProcessInstanceByKey("executionProcess");
    ClockUtil.setCurrentTime(createArtificalDate(10));
    runtimeService.startProcessInstanceByKey("executionProcess");

    runtimeService.startProcessInstanceByKey("changeVariablesProcess");
    runtimeService.startProcessInstanceByKey("changeVariablesProcess");
    runtimeService.startProcessInstanceByKey("changeVariablesProcess");
    runtimeService.startProcessInstanceByKey("changeVariablesProcess");

    runtimeService.startProcessInstanceByKey("asyncAfter");

    ClockUtil.reset();

    ProcessInstance pi = runtimeService.startProcessInstanceByKey("changeVariablesProcess");
    TaskService taskService = engine.getTaskService();
    Task task = taskService.createTaskQuery().processInstanceId(pi.getId()).singleResult();
    taskService.setVariableLocal(task.getId(), "localTaskVariable", "foo");

    CaseService caseService = engine.getCaseService();
    caseService
      .withCaseDefinitionByKey("loanApplicationCase")
      .setVariable("aVariable", "abc")
      .setVariable("anotherVariable", "xyz")
      .create();

    CaseExecutionQuery query = caseService.createCaseExecutionQuery();

    String stageId = query
        .activityId("PI_collectDataStage")
        .singleResult()
        .getId();

    caseService
      .withCaseExecution(stageId)
      .manualStart();

    String first = query
        .activityId("PI_captureAppDataHumanTask")
        .singleResult()
        .getId();

    caseService
      .withCaseExecution(first)
      .manualStart();

    String second = query
        .activityId("PI_obtainCreditWorthinessHumanTask")
        .singleResult()
        .getId();

    caseService
      .withCaseExecution(second)
      .manualStart();

    String third = query
        .activityId("PI_reviewDocumentsHumanTask")
        .singleResult()
        .getId();

    caseService
      .withCaseExecution(third)
      .manualStart();

    String fourth = query
        .activityId("PI_obtainSchufaInfoProcessTask")
        .singleResult()
        .getId();

    caseService
      .withCaseExecution(fourth)
      .manualStart();

    Task standaloneTask = taskService.newTask();
    standaloneTask.setName("A Standalone Task");
    standaloneTask.setAssignee("jonny1");
    taskService.saveTask(standaloneTask);

    String standaloneTaskId = taskService
        .createTaskQuery()
        .taskName("A Standalone Task")
        .singleResult()
        .getId();

    taskService.setVariable(standaloneTaskId, "aVariable", "abc");
    taskService.setVariable(standaloneTaskId, "anotherVariable", 123456l);

    startInvoiceInstances(engine);

    new Thread(){
      public void run() {
        ((ProcessEngineImpl) engine).getProcessEngineConfiguration().getJobExecutor().start();
      }
    }.start();
  }

  private void createAdminDemoData(ProcessEngine engine) throws Exception {
    UserDto user = new UserDto();
    UserProfileDto profile = new UserProfileDto();
    profile.setId("jonny1");
    profile.setFirstName("Jonny");
    profile.setLastName("Prosciutto");
    UserCredentialsDto credentials = new UserCredentialsDto();
    credentials.setPassword("jonny1");
    user.setProfile(profile);
    user.setCredentials(credentials);

    // manually perform setup
    new SetupResource().createInitialUser(engine.getName(), user);
  }

  private void createTasklistDemoData(ProcessEngine engine) {

    // create invoice demo data
    new InvoiceDemoDataGenerator().createDemoData(engine);
  }

  private Date createArtificalDate(int offset) {
    DateTime dt = new DateTime();
    dt = dt.minusDays(offset);
    dt = dt.minusHours(offset);
    dt = dt.minusMinutes(offset);
    dt = dt.minusSeconds(offset);
    return dt.toDate();
  }


  private void startInvoiceInstances(ProcessEngine processEngine) {

    InputStream invoiceInputStream = getClass().getClassLoader().getResourceAsStream("invoice.pdf");

    // process instance 1
    processEngine.getRuntimeService().startProcessInstanceByKey("invoice", createVariables()
        .putValue("creditor", "Great Pizza for Everyone Inc.")
        .putValue("amount", 30.00d)
        .putValue("invoiceCategory", "Travel Expenses")
        .putValue("invoiceNumber", "GPFE-23232323")
        .putValue("invoiceDocument", fileValue("invoice.pdf")
            .file(invoiceInputStream)
            .mimeType("application/pdf")
            .create()));

    IoUtil.closeSilently(invoiceInputStream);
    invoiceInputStream = getClass().getClassLoader().getResourceAsStream("invoice.pdf");

    // process instance 2
    ProcessInstance pi = processEngine.getRuntimeService().startProcessInstanceByKey("invoice", createVariables()
        .putValue("creditor", "Bobby's Office Supplies")
        .putValue("amount", 900.00d)
        .putValue("invoiceCategory", "Misc")
        .putValue("invoiceNumber", "BOS-43934")
        .putValue("invoiceDocument", fileValue("invoice.pdf")
            .file(invoiceInputStream)
            .mimeType("application/pdf")
            .create()));
    try {
      Calendar calendar = Calendar.getInstance();
      calendar.add(Calendar.DAY_OF_MONTH, -14);
      ClockUtil.setCurrentTime(calendar.getTime());
      processEngine.getIdentityService().setAuthentication("demo", Arrays.asList(Groups.CAMUNDA_ADMIN));
      Task task = processEngine.getTaskService().createTaskQuery().processInstanceId(pi.getId()).singleResult();
      processEngine.getTaskService().claim(task.getId(), "demo");
      processEngine.getTaskService().complete(task.getId(), createVariables().putValue("approved", true));
    }
    finally{
      ClockUtil.reset();
      processEngine.getIdentityService().clearAuthentication();
    }

    IoUtil.closeSilently(invoiceInputStream);
    invoiceInputStream = getClass().getClassLoader().getResourceAsStream("invoice.pdf");

    // process instance 3
    pi = processEngine.getRuntimeService().startProcessInstanceByKey("invoice", createVariables()
        .putValue("creditor", "Papa Steve's all you can eat")
        .putValue("amount", 10.99d)
        .putValue("invoiceCategory", "Travel Expenses")
        .putValue("invoiceNumber", "PSACE-5342")
        .putValue("invoiceDocument", fileValue("invoice.pdf")
            .file(invoiceInputStream)
            .mimeType("application/pdf")
            .create()));

  }

  protected void createReportDemoData(ProcessEngine engine) {

    LOGGER.info("Generating random report data for cockpit");

    Calendar instance = Calendar.getInstance();
    Date currentTime = instance.getTime();

    BpmnModelInstance model = createProcessWithUserTask("my-reporting-process", "Report Process");

    startAndCompleteReportingInstances(engine, model, currentTime, 24);
    startAndCompleteReportingInstances(engine, model, currentTime, 16);
    startAndCompleteReportingInstances(engine, model, currentTime, 8);
  }

  protected void startAndCompleteReportingInstances(ProcessEngine engine, BpmnModelInstance model, Date currentTime, int offset) {
    Calendar calendar = Calendar.getInstance();

    int currentMonth = calendar.get(Calendar.MONTH);
    int currentYear = calendar.get(Calendar.YEAR);

    calendar.add(Calendar.MONTH, offset * (-1));
    ClockUtil.setCurrentTime(calendar.getTime());

    createDeployment(engine, "reports", model);

    RuntimeService runtimeService = engine.getRuntimeService();
    TaskService taskService = engine.getTaskService();

    while (calendar.get(Calendar.YEAR) < currentYear || calendar.get(Calendar.MONTH) <= currentMonth) {

      int numOfInstances = getRandomBetween(10, 50);

      for(int i = 0; i <= numOfInstances; i++) {
        ProcessInstance pi = runtimeService.startProcessInstanceByKey("my-reporting-process");

        try {

          int min = getRandomBetween(1, 10);
          int max = offset > 0 ? offset * 30 : min;
          int randomDuration = getRandomBetween(min, max);

          Calendar calendarInstance = Calendar.getInstance();
          calendarInstance.setTime(ClockUtil.getCurrentTime());
          calendarInstance.add(Calendar.DAY_OF_YEAR, randomDuration);
          ClockUtil.setCurrentTime(calendarInstance.getTime());

          String processInstanceId = pi.getId();
          String taskId = taskService
              .createTaskQuery()
              .processInstanceId(processInstanceId)
              .singleResult()
              .getId();
          taskService.complete(taskId);

        }
        finally {
          ClockUtil.setCurrentTime(calendar.getTime());
        }
      }

      offset--;
      calendar.add(Calendar.MONTH, 1);
      ClockUtil.setCurrentTime(calendar.getTime());
    }

    ClockUtil.reset();
  }

  protected int getRandomBetween(int min, int max) {
    return (int)(Math.random() * (max - min) + min);
  }

  protected void createDeployment(ProcessEngine engine, String deploymentName, BpmnModelInstance model) {
    engine.getRepositoryService()
      .createDeployment()
      .name(deploymentName)
      .addModelInstance("path/to/my/process.bpmn", model)
      .deploy();
  }

  protected BpmnModelInstance createProcessWithUserTask(String key, String name) {
    return Bpmn.createExecutableProcess(key)
      .name(name)
      .startEvent()
      .userTask()
      .endEvent()
    .done();
  }

}
