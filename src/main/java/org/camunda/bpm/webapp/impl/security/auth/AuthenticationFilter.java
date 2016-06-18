/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.bpm.webapp.impl.security.auth;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import org.camunda.bpm.cockpit.Cockpit;
import org.camunda.bpm.engine.AuthorizationService;
import org.camunda.bpm.engine.ProcessEngine;
import static org.camunda.bpm.engine.authorization.Permissions.ACCESS;
import static org.camunda.bpm.engine.authorization.Resources.APPLICATION;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.Tenant;
import org.camunda.bpm.engine.rest.exception.RestException;
import org.camunda.bpm.engine.rest.spi.ProcessEngineProvider;
import org.camunda.bpm.webapp.impl.security.SecurityActions;
import org.camunda.bpm.webapp.impl.security.SecurityActions.SecurityAction;

/**
 * <p>
 * Servlet {@link Filter} implementation responsible for populating the
 * {@link Authentications#getCurrent()} thread-local (ie. binding the current
 * set of authentications to the current thread so that it may easily be
 * obtained by application parts not having access to the current session.</p>
 *
 * @author Daniel Meyer
 * @author nico.rehwaldt
 */
public class AuthenticationFilter implements Filter {

    private static final String[] APPS = new String[]{"cockpit", "tasklist"};

    /**
     * Destroy method for this filter
     */
    public void destroy() {
    }

    /**
     * Init method for this filter
     */
    public void init(FilterConfig filterConfig) {

    }

    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;

        // get authentication from session
        Authentications authentications = Authentications.getFromSession(req.getSession());

        UserAuthentication auth = getMyAuthentication(req, authentications);
        if (auth != null) {
            authentications.addAuthentication(auth);
//            System.out.println("Adding authentication " + auth.identityId + "  " + auth.identityId);
        }

        Authentications.setCurrent(authentications);

//        for (Entry<String, Authentication> au : authentications.authentications.entrySet()) {
//            System.out.println("Map entry" + au.getKey() + "  " + au.getValue().identityId + ": " + au.getValue().processEngineName);
//        }

        try {

            SecurityActions.runWithAuthentications(new SecurityAction<Void>() {
                public Void execute() {
                    try {
                        chain.doFilter(request, response);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return null;
                }
            }, authentications);
        } finally {
            Authentications.clearCurrent();
            Authentications.updateSession(req.getSession(), authentications);
        }
    }

    private UserAuthentication getMyAuthentication(final HttpServletRequest req, Authentications authentications) {
        String processEngineName = "default";
        String username = ImpersonationServlet.getUsername(req.getHeader("REMOTE_USER"));
//        System.out.println("Impersonation: "+username);
        //If impersonation is not active
        if(username == null) username = (String) req.getHeader("REMOTE_USER");
        if (username != null) {
            for (Authentication aut : authentications.getAuthentications()) {
                if (aut.getName().equals(username)) {
                    // already in the list - nothing to do
                    return null;
                }
            }

            UserAuthentication auth = new UserAuthentication(username, processEngineName);
            final ProcessEngine processEngine = lookupProcessEngine(processEngineName);
            auth.setGroupIds(getGroupsOfUser(processEngine, username));
            auth.setTenantIds(getTenantsOfUser(processEngine, username));
            // check user's app authorizations
            AuthorizationService authorizationService = processEngine.getAuthorizationService();
            HashSet<String> authorizedApps = new HashSet<String>();
            authorizedApps.add("admin");
            if (processEngine.getProcessEngineConfiguration().isAuthorizationEnabled()) {
                for (String application : APPS) {
                    if (isAuthorizedForApp(authorizationService, username, auth.getGroupIds(), application)) {
                        authorizedApps.add(application);
                    }
                }

            } else {
                Collections.addAll(authorizedApps, APPS);
            }
            auth.setAuthorizedApps(authorizedApps);

            return auth;
        } else {
            return null;
        }
    }

    public static String getStackTrace(Throwable t) {
        String stackTrace = null;
        try {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            t.printStackTrace(pw);
            pw.close();
            sw.close();
            stackTrace = sw.getBuffer().toString();
        } catch (Exception ex) {
        }
        return stackTrace;
    }

    protected void clearProcessEngineAuthentications(Authentications authentications) {
        for (Authentication authentication : authentications.getAuthentications()) {
            ProcessEngine processEngine = Cockpit.getProcessEngine(authentication.getProcessEngineName());
            if (processEngine != null) {
                processEngine.getIdentityService().clearAuthentication();
            }
        }
    }

    protected List<String> getGroupsOfUser(ProcessEngine engine, String userId) {
        List<Group> groups = engine.getIdentityService().createGroupQuery()
                .groupMember(userId)
                .list();

        List<String> groupIds = new ArrayList<String>();
        for (Group group : groups) {
            groupIds.add(group.getId());
        }
        return groupIds;
    }

    protected List<String> getTenantsOfUser(ProcessEngine engine, String userId) {
        List<Tenant> tenants = engine.getIdentityService().createTenantQuery()
                .userMember(userId)
                .includingGroupsOfUser(true)
                .list();

        List<String> tenantIds = new ArrayList<String>();
        for (Tenant tenant : tenants) {
            tenantIds.add(tenant.getId());
        }
        return tenantIds;
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

    private Response unauthorized() {
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    private Response forbidden() {
        return Response.status(Response.Status.FORBIDDEN).build();
    }

    protected boolean isAuthorizedForApp(AuthorizationService authorizationService, String username, List<String> groupIds, String application) {
        return authorizationService.isUserAuthorized(username, groupIds, ACCESS, APPLICATION, application);
    }

    private Response notFound() {
        return Response.status(Response.Status.NOT_FOUND).build();
    }

}
