/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ranger.authorization.presto.authorizer;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.SystemAccessControl;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;

import javax.inject.Inject;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class RangerSystemAccessControl
        implements SystemAccessControl
{
    private static final String RANGER_PLUGIN_TYPE = "presto";
    private static final String RANGER_PRESTO_AUTHORIZER_IMPL_CLASSNAME = "org.apache.ranger.authorization.presto.authorizer.RangerSystemAccessControl";

    private static RangerPluginClassLoader rangerPluginClassLoader;
    private SystemAccessControl rangerSystemAccessControl;

    @Inject
    public RangerSystemAccessControl(RangerConfig rangerConfig)
    {
        this.init(rangerConfig);
    }

    private void init(RangerConfig config)
    {
        try {
            rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

            @SuppressWarnings("unchecked")
            Class<SystemAccessControl> cls = (Class<SystemAccessControl>) Class.forName(RANGER_PRESTO_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

            activatePluginClassLoader();

            Map<String, String> configMap = new HashMap<>();
            if (config.getKeytab() != null && config.getPrincipal() != null) {
                configMap.put("ranger.keytab", config.getKeytab());
                configMap.put("ranger.principal", config.getPrincipal());
            }
            rangerSystemAccessControl = cls.getDeclaredConstructor(Map.class).newInstance(configMap);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
        finally {
            deactivatePluginClassLoader();
        }
    }

    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanSetUser(principal, userName);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denySetUser(principal, userName);
        }
    }

    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, String propertyName)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanSetSystemSessionProperty(identity, propertyName);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denySetSystemSessionProperty(propertyName);
        }
    }

    @Override
    public void checkCanAccessCatalog(Identity identity, String catalogName)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanAccessCatalog(identity, catalogName);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyCatalogAccess(catalogName);
        }
    }

    @Override
    public Set<String> filterCatalogs(Identity identity, Set<String> catalogs)
    {
        return catalogs;
    }

    @Override
    public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanCreateSchema(identity, schema);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyCreateSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanDropSchema(Identity identity, CatalogSchemaName schema)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanDropSchema(identity, schema);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyDropSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanRenameSchema(identity, schema, newSchemaName);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
        }
    }

    @Override
    public void checkCanShowSchemas(Identity identity, String catalogName)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanShowSchemas(identity, catalogName);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyShowSchemas();
        }
    }

    @Override
    public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames)
    {
        return schemaNames;
    }

    @Override
    public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanCreateTable(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDropTable(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanDropTable(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanRenameTable(identity, table, newTable);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanShowTablesMetadata(Identity identity, CatalogSchemaName schema)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanShowTablesMetadata(identity, schema);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
        }
    }

    @Override
    public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames)
    {
        return tableNames;
    }

    @Override
    public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanAddColumn(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanDropColumn(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanRenameColumn(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanSelectFromColumns(identity, table, columns);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
        }
    }

    @Override
    public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanInsertIntoTable(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanDeleteFromTable(identity, table);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanCreateView(Identity identity, CatalogSchemaTableName view)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanCreateView(identity, view);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDropView(Identity identity, CatalogSchemaTableName view)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanDropView(identity, view);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(identity, table, columns);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
        }
    }

    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName)
    {
        try {
            activatePluginClassLoader();
            rangerSystemAccessControl.checkCanSetCatalogSessionProperty(identity, catalogName, propertyName);
        }
        catch (AccessDeniedException e) {
            deactivatePluginClassLoader();
            throw e;
        }
        catch (Exception e) {
            deactivatePluginClassLoader();
            AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
        }
    }

    private void activatePluginClassLoader()
    {
        if (rangerPluginClassLoader != null) {
            rangerPluginClassLoader.activate();
        }
    }

    private void deactivatePluginClassLoader()
    {
        if (rangerPluginClassLoader != null) {
            rangerPluginClassLoader.deactivate();
        }
    }
}
