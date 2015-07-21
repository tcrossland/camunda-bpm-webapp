package org.camunda.bpm.webapp.impl.security.auth;

import org.camunda.bpm.engine.AuthorizationService;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.rest.exception.RestException;
import org.camunda.bpm.engine.rest.spi.ProcessEngineProvider;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;

import javax.ws.rs.core.Response;
import java.util.*;

import static org.camunda.bpm.engine.authorization.Permissions.ACCESS;
import static org.camunda.bpm.engine.authorization.Resources.APPLICATION;

/**
 * Event Handler to store authentications after CAS login success.
 */
public class AuthenticationSuccessListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {
    private List<String> applications;

    public List<String> getApplications() {
        return applications;
    }

    public void setApplications(List<String> applications) {
        this.applications = applications;
    }

    @Override
    public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
        org.springframework.security.core.Authentication auth = event.getAuthentication();
        String engineName = "default"; // TODO
        String username = auth.getName();

        final ProcessEngine processEngine = lookupProcessEngine(engineName);

        // get user's groups
        final List<Group> groupList = processEngine.getIdentityService().createGroupQuery()
                .groupMember(username)
                .list();

        // transform into array of strings:
        List<String> groupIds = new ArrayList<String>();

        for (Group group : groupList) {
            groupIds.add(group.getId());
        }

        // check user's app authorizations
        AuthorizationService authorizationService = processEngine.getAuthorizationService();

        HashSet<String> authorizedApps = new HashSet<String>();
        authorizedApps.add("admin");

        if (processEngine.getProcessEngineConfiguration().isAuthorizationEnabled()) {
            for (String application : applications) {
                if (isAuthorizedForApp(authorizationService, username, groupIds, application)) {
                    authorizedApps.add(application);
                }
            }
        } else {
            authorizedApps.addAll(applications);
        }

        final Authentications authentications = Authentications.getCurrent();

        // create new authentication
        UserAuthentication newAuthentication = new UserAuthentication(username, groupIds, engineName, authorizedApps);
        authentications.addAuthentication(newAuthentication);
    }

    protected ProcessEngine lookupProcessEngine(String engineName) {
        ServiceLoader<ProcessEngineProvider> serviceLoader = ServiceLoader.load(ProcessEngineProvider.class);
        Iterator<ProcessEngineProvider> iterator = serviceLoader.iterator();

        if (iterator.hasNext()) {
            ProcessEngineProvider provider = iterator.next();
            return provider.getProcessEngine(engineName);

        } else {
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR, "Could not find an implementation of the " + ProcessEngineProvider.class + "- SPI");
        }
    }

    protected boolean isAuthorizedForApp(AuthorizationService authorizationService, String username, List<String> groupIds, String application) {
        return authorizationService.isUserAuthorized(username, groupIds, ACCESS, APPLICATION, application);
    }
}
