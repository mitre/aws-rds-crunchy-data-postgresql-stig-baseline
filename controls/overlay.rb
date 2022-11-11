# encoding: utf-8

include_controls 'crunchy-data-postgresql-stig-baseline' do

  control "V-233511" do

   sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    describe sql.query('SHOW port;', [input('pg_db')]) do
      its('output') { should eq input('pg_port') }
    end

  end

  control "V-233512" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233513" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233514" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233515" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
  
  control "V-233516" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    describe sql.query('SHOW client_min_messages;', [input('pg_db')]) do
      its('output') { should match /^error$/i }
    end
  end

  control "V-233517" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233518" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233519" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
  
  control 'V-233520' do
  if input('windows_runner')
    describe 'Requires manual review at this time.' do
      skip 'Requires manual review at this time.'
    end
  else
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r AND r.rolname != \'rdsadmin\';'
    roles_query = sql.query(roles_sql, [input('pg_db')])
    roles = roles_query.lines

    roles.each do |role|
      next if input('pg_superusers').include?(role)

      superuser_sql = 'SELECT r.rolsuper FROM pg_catalog.pg_roles r '\
        "WHERE r.rolname = '#{role}';"

      describe sql.query(superuser_sql, [input('pg_db')]) do
        its('output') { should_not eq 't' }
      end
    end

    authorized_owners = input('pg_superusers')
    owners = authorized_owners.join('|')

    object_granted_privileges = 'arwdDxtU'
    object_public_privileges = 'r'
    object_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
      "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
    object_acl_regex = Regexp.new(object_acl)

    objects_sql = 'SELECT n.nspname, c.relname, c.relkind '\
      'FROM pg_catalog.pg_class c '\
      'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
      "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f') "\
      "AND n.nspname !~ '^pg_' AND pg_catalog.pg_table_is_visible(c.oid);"

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate AND datname != \'rdsadmin\';'
    databases_query = sql.query(databases_sql, [input('pg_db')])
    databases = databases_query.lines

    databases.each do |database|
      rows = sql.query(objects_sql, [database])
      next unless rows.methods.include?(:output) # Handle connection disabled on database

      objects = rows.lines

      objects.each do |obj|
        schema, object, type = obj.split('|')
        relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
          'n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c '\
          'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
          "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
          "AND c.relkind = '#{type}';"

        describe sql.query(relacl_sql, [database]) do
          its('output') { should match object_acl_regex }
        end
      end
    end
  end
end      
      
  control "V-233521" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in transmission' do
      skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
      having organization-defined security label values with information in transmission'
    end
  end

  control 'V-233523' do
    if !input('windows_runner')
      sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
      authorized_owners = input('pg_superusers')
      owners = authorized_owners.join('|')
  
      object_granted_privileges = 'arwdDxtU'
      object_public_privileges = 'r'
      object_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
        "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
      object_acl_regex = Regexp.new(object_acl)
  
      pg_settings_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
        "=rw)\/\\w+,?)+)\\|pg_catalog\\|pg_settings\\|v"
      pg_settings_acl_regex = Regexp.new(pg_settings_acl)
  
      tested = []
      objects_sql = "SELECT n.nspname, c.relname, c.relkind "\
        "FROM pg_catalog.pg_class c "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
        "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f');"
  
      databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate AND datname != \'rdsadmin\';'
      databases_query = sql.query(databases_sql, [input('pg_db')])
      databases = databases_query.lines
  
      databases.each do |database|
        rows = sql.query(objects_sql, [database])
        if rows.methods.include?(:output) # Handle connection disabled on database
          objects = rows.lines
  
          objects.each do |obj|
            unless tested.include?(obj)
              schema, object, type = obj.split('|')
              relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
                "n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "\
                "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
                "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
                "AND c.relkind = '#{type}';"
  
              sql_result=sql.query(relacl_sql, [database])
  
              describe.one do
                describe sql_result do
                  its('output') { should match object_acl_regex }
                end
  
                describe sql_result do
                  its('output') { should match pg_settings_acl_regex }
                end
              end
              tested.push(obj)
            end
          end
        end
      end
    else
      describe 'This must be manually reviewed at this time' do
        skip 'This must be manually reveiwed at this time'
      end
    end
  end

  control "V-233525" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in storage' do
    skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in storage'
    end
  end

  control "V-233526" do
    describe 'A manual review is required to ensure PostgreSQL checks the validity of all data inputs except those
    specifically identified by the organization' do
    skip 'A manual review is required to ensure PostgreSQL checks the validity of all data inputs except those
    specifically identified by the organization'
    end
  end

  control "V-233526" do
    describe 'A manual review is require to ensure PostgreSQL and associated applications reserve the use of dynamic
    code execution for situations that require it.' do
    skip 'A manual review is require to ensure PostgreSQL and associated applications reserve the use of dynamic
    code execution for situations that require it.'
    end 
  end

  control "V-233528" do
    describe 'PostgreSQL and associated applications, when making use of dynamic code
    execution, must scan input data for invalid values that may indicate a code injection attack' do
    skip 'PostgreSQL and associated applications, when making use of dynamic code
    execution, must scan input data for invalid values that may indicate a code injection attack'
    end
  end

  control "V-233529" do
    describe 'A manual review is required to ensure PostgreSQL allocates audit record storage capacity in accordance
    with organization-defined audit record storage requirements' do
    skip 'A manual review is required to ensure PostgreSQL allocates audit record storage capacity in accordance
    with organization-defined audit record storage requirements'
    end
  end

  control "V-233530" do
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  authorized_owners = input('pg_superusers')
  pg_db = input('pg_db')
  pg_owner = input('pg_owner')

  databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{pg_db}';"
  databases_query = sql.query(databases_sql, [pg_db])
  databases = databases_query.lines
  types = %w(t s v) # tables, sequences views

  databases.each do |database|
    schemas_sql = ''
    functions_sql = ''

    if database == 'postgres'
      schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_namespace n "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin';"
    else
      schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_namespace n "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
        "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
        "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
        "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
        "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema';"
    end

    connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
      "accepting connections"
    connection_error_regex = Regexp.new(connection_error)
    
    sql_result=sql.query(schemas_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end

    sql_result=sql.query(functions_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end

    types.each do |type|
      objects_sql = ''

      if database == 'postgres'
        objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
          "WHERE c.relkind IN ('#{type}','s','') "\
          "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
          " AND n.nspname !~ '^pg_toast';"
      else
        objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
          "WHERE c.relkind IN ('#{type}','s','') "\
          "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
          "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'"\
          " AND n.nspname !~ '^pg_toast';"
      end

      sql_result=sql.query(objects_sql, [database])

      describe.one do
        describe sql_result do
          its('output') { should eq '' }
        end

        describe sql_result do
          it { should match connection_error_regex }
        end
      end
    end
  end
end

control "V-233531" do
  describe 'Requires manual review of the RDS audit log system at this time.' do
    skip 'Requires manual review of the RDS audit log system at this time.'
  end
end

control "V-233533" do
  describe 'Requires manual review of the RDS audit log system at this time.' do
    skip 'Requires manual review of the RDS audit log system at this time.'
  end
end

  control "V-233534" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [input('pg_db')])
    roles = roles_query.lines

    roles.each do |role|
      unless input('pg_superusers').include?(role)
        superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
          "WHERE r.rolname = '#{role}';"

        describe sql.query(superuser_sql, [input('pg_db')]) do
          its('output') { should_not eq 't' }
        end
      end
    end
  end

  control "V-233535" do
    describe 'A manual review is required to ensure PostgreSQL provides an immediate real-time alert to appropriate
      support staff of all audit failure events requiring real-time alerts' do
      skip 'A manual review is required to ensure PostgreSQL provides an immediate real-time alert to appropriate
      support staff of all audit failure events requiring real-time alerts'
    end
  end

  control "V-233539" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
    authorized_owners = input('pg_superusers')
    pg_db = input('pg_db')
    pg_owner = input('pg_owner')


    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{pg_db}';"
    databases_query = sql.query(databases_sql, [pg_db])
    databases = databases_query.lines
    types = %w(t s v) # tables, sequences views

    databases.each do |database|
      schemas_sql = ''
      functions_sql = ''

      if database == 'postgres'
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin';"
      else
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
          "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
          "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema';"
      end

      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        "accepting connections"
      connection_error_regex = Regexp.new(connection_error)

      sql_result=sql.query(schemas_sql, [database])

      describe.one do
        describe sql_result do
          its('output') { should eq '' }
        end

        describe sql_result do
          it { should match connection_error_regex }
        end
      end

      sql_result=sql.query(functions_sql, [database])

      describe.one do
        describe sql_result do
          its('output') { should eq '' }
        end

        describe sql_result do
          it { should match connection_error_regex }
        end
      end

      types.each do |type|
        objects_sql = ''

        if database == 'postgres'
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "
            "AND n.nspname !~ '^pg_toast';"
        else
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
            "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin' "\
            "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'"\
            " AND n.nspname !~ '^pg_toast';"
        end

        sql_result=sql.query(objects_sql, [database])

        describe.one do
          describe sql_result do
            its('output') { should eq '' }
          end

          describe sql_result do
            it { should match connection_error_regex }
          end
        end
      end
    end
  end


  control "V-233540" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233541" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233542" do
    describe 'A manual review is required to ensure PostgreSQL includes additional, more detailed, organization-defined
      information in the audit records for audit events identified by type,
      location, or subject' do
      skip 'A manual review is required to ensure PostgreSQL includes additional, more detailed, organization-defined
      information in the audit records for audit events identified by type,
      location, or subject'
    end
  end

  control "V-233543" do
    desc "check", "Functions in PostgreSQL can be created with the SECURITY DEFINER
    option. When SECURITY DEFINER functions are executed by a user, said function
    is run with the privileges of the user who created it. 
    To list all functions that have SECURITY DEFINER, as, the database
    administrator (shown here as \"postgres\"), run the following SQL: 
    $ sudo su - postgres 
    $ psql -c \"SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig
    FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_roles a
    ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL\" 
    In the query results, a prosecdef value of \"t\" on a row indicates that that
    function uses privilege elevation. 
    If elevation of PostgreSQL privileges is utilized but not documented, this is a
    finding. 
    If elevation of PostgreSQL privileges is documented, but not implemented as
    described in the documentation, this is a finding. 
    If the privilege-elevation logic can be invoked in ways other than intended, or
    in contexts other than intended, or by subjects/principals other than intended,
    this is a finding."

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    security_definer_sql = "SELECT nspname, proname, prosecdef "\
      "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "\
      "JOIN pg_roles a ON a.oid = p.proowner WHERE prosecdef = 't';"

    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{pg_db}';"
    databases_query = sql.query(databases_sql, [pg_db])
    databases = databases_query.lines

    databases.each do |database|
      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        "accepting connections"
      connection_error_regex = Regexp.new(connection_error)

      sql_result=sql.query(security_definer_sql, [database])

      describe.one do
        describe sql_result do
          its('output') { should eq '' }
        end

        describe sql_result do
          it { should match connection_error_regex }
        end
      end
    end
  end

  control "V-233544" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233545" do
    describe 'Requires manual review of the use of a centralized logging solution at this time.' do
      skip 'Requires manual review of the use of a centralized logging solution at this time.'
    end
  end

  control "V-233546" do
    pg_owner = input('pg_owner')
    pg_dba = input('pg_dba')
    pg_dba_password = input('pg_dba_password')
    pg_db = input('pg_db')
    pg_host = input('pg_host')
    pg_object_granted_privileges = input('pg_object_granted_privileges')
    pg_object_public_privileges = input('pg_object_public_privileges')
    pg_object_exceptions = input('pg_object_exceptions')
    exceptions = "#{pg_object_exceptions.map { |e| "'#{e}'" }.join(',')}"
    object_acl = "^(((#{pg_owner}|rdsadmin=[#{pg_object_granted_privileges}]+|"\
      "=[#{pg_object_public_privileges}]+)\\/\\w+,?)+|)$"
    schemas = ['pg_catalog', 'information_schema']
    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    schemas.each do |schema|
    objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
      "pg_catalog.array_to_string(c.relacl, E',') FROM pg_catalog.pg_class c "\
      "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
      "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f') "\
      "AND n.nspname ~ '^(#{schema})$' "\
      "AND pg_catalog.array_to_string(c.relacl, E',') !~ '#{object_acl}' "\
      "AND c.relname NOT IN (#{exceptions});"

    describe sql.query(objects_sql, [pg_db]) do
      its('output') { should eq '' }
    end

    functions_sql = "SELECT n.nspname, p.proname, "\
      "pg_catalog.pg_get_userbyid(n.nspowner) "\
      "FROM pg_catalog.pg_proc p "\
      "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
      "WHERE n.nspname ~ '^(#{schema})$' "\
      "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' AND pg_catalog.pg_get_userbyid(n.nspowner) <> 'rdsadmin';"

    describe sql.query(functions_sql, [pg_db]) do
      its('output') { should eq '' }
    end
  end
end

  control "V-233547" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233549" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233550" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233551" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233552" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233553" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233554" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233555" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233556" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233557" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233558" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233559" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233560" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233561" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233562" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233563" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233564" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233566" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233567" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233568" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233569" do
    desc "check", "First, as the database administrator, verify that log_connections
    and log_disconnections are enabled by running the following SQL:
    $ sudo su - postgres
    $ psql -c \"SHOW log_connections\"
    $ psql -c \"SHOW log_disconnections\"
    If either is off, this is a finding.
    Next, verify that log_line_prefix contains sufficient information by running
    the following SQL:
    $ sudo su - postgres
    $ psql -c \"SHOW log_line_prefix\"
    If log_line_prefix does not contain at least %t %u %d %p, this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.
    To ensure that logging is enabled, review supplementary content APPENDIX-C for
    instructions on enabling logging. 
    First, as the database administrator (shown here as \"postgres\"), edit
    postgresql.conf: 
    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 
    Edit the following parameters as such: 
    log_connections = on 
    log_disconnections = on 
    log_line_prefix = '< %t %u %d %p: >' 
    Where: 
    * %t is the time and date without milliseconds
    * %u is the username 
    * %d is the database 
    * %p is the Process ID for the connection 
    Now, as the system administrator, reload the server with the new configuration: 
    # SYSTEMD SERVER ONLY 
    $ sudo systemctl reload postgresql-${PGVER?}
    # INITD SERVER ONLY 
    $ sudo service postgresql-${PGVER?} reload"

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    describe sql.query('SHOW log_connections;', [pg_db]) do
      its('output') { should_not match /off|false/i }
    end

    describe sql.query('SHOW log_disconnections;', [pg_db]) do
      its('output') { should_not match /off|false/i }
    end

    log_line_prefix_escapes = %w(%t %u %d %p)

    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end
end

  control "V-233570" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233571" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233572" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233573" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233574" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233575" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233576" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233577" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages this capability' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages this capability'
    end
  end

  control "V-233581" do
    desc "check", "Note: The following instructions use the PGDATA environment
    variable. See supplementary content APPENDIX-F for instructions on configuring
    PGDATA.
    First, as the database administrator (shown here as \"postgres\"), verify the
    current log_line_prefix setting by running the following SQL:
    $ sudo su - postgres
    $ psql -c \"SHOW log_line_prefix\"
    If log_line_prefix does not contain %t, this is a finding.
    Next check the logs to verify time stamps are being logged:
    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_log/<latest_log>
    < 2016-02-23 12:53:33.947 EDT postgres postgres 570bd68d.3912 >LOG: connection
    authorized: user=postgres database=postgres
    < 2016-02-23 12:53:41.576 EDT postgres postgres 570bd68d.3912 >LOG: AUDIT:
    SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE test_srg(id INT);,<none>
    < 2016-02-23 12:53:44.372 EDT postgres postgres 570bd68d.3912 >LOG:
    disconnection: session time: 0:00:10.426 user=postgres database=postgres
    host=[local]
    If time stamps are not being logged, this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.
    PostgreSQL will not log anything if logging is not enabled. To ensure that
    logging is enabled, review supplementary content APPENDIX-C for instructions on
    enabling logging. 
    If logging is enabled the following configurations must be made to log events
    with time stamps:  
    First, as the database administrator (shown here as \"postgres\"), edit
    postgresql.conf: 
    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 
    Add %m to log_line_prefix to enable time stamps with milliseconds: 
    log_line_prefix = '< %t >' 
    Now, as the system administrator, reload the server with the new configuration: 
    # SYSTEMD SERVER ONLY 
    $ sudo systemctl reload postgresql-${PGVER?}
    # INITD SERVER ONLY 
    $ sudo service postgresql-${PGVER?} reload"

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')
    
    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    describe sql.query('SHOW log_line_prefix;', [pg_db]) do
      its('output') { should match '%t' }
    end
  end

  control "V-233582" do
    desc "check", "Check PostgreSQL settings and existing audit records to verify a
    user name associated with the event is being captured and stored with the audit
    records. If audit records exist without specific user information, this is a
    finding.
    First, as the database administrator (shown here as \"postgres\"), verify the
    current setting of log_line_prefix by running the following SQL:
    $ sudo su - postgres
    $ psql -c \"SHOW log_line_prefix\"
    If log_line_prefix does not contain %t, %u, %d, %p, %r, this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.
    Logging must be enabled in order to capture the identity of any user/subject or
    process associated with an event. To ensure that logging is enabled, review
    supplementary content APPENDIX-C for instructions on enabling logging. 
    To enable username, database name, process ID, remote host/port and application
    name in logging, as the database administrator (shown here as \"postgres\"),
    edit the following in postgresql.conf: 
    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 
    log_line_prefix = '< %t %u %d %p %r >' 
    Now, as the system administrator, reload the server with the new configuration: 
    # SYSTEMD SERVER ONLY 
    $ sudo systemctl reload postgresql-${PGVER?}
    # INITD SERVER ONLY 
    $ sudo service postgresql-${PGVER?} reload"

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    log_line_prefix_escapes = %w(%t %u %d %p %r)

    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end
  end

  control "V-233583" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end


  control "V-233585" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233588" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    pg_superusers = input('pg_superusers')
    rds_superusers = input('rds_superusers')
    pg_db = input('pg_db')
    pg_owner = input('pg_owner')

    privileges = %w(rolcreatedb rolcreaterole rolsuper)
    
    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [pg_db])
    roles = roles_query.lines

    roles.each do |role|
      unless pg_superusers.include?(role) || rds_superusers.include?(role)
        privileges.each do |privilege|
          privilege_sql = "SELECT r.#{privilege} FROM pg_catalog.pg_roles r "\
            "WHERE r.rolname = '#{role}';"

          describe sql.query(privilege_sql, [pg_db]) do
            its('output') { should_not eq 't' }
          end
        end
      end
    end
  end

  control "V-233591" do
    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.
    To ensure that logging is enabled, review supplementary content APPENDIX-C for
    instructions on enabling logging. 
    If logging is enabled the following configurations can be made to log the
    source of an event. 
    First, as the database administrator, edit postgresql.conf: 
    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 
    ###### Log Line Prefix 
    Extra parameters can be added to the setting log_line_prefix to log source of
    event: 
    # %u = user name 
    # %d = database name 
    # %r = remote host and port 
    # %p = process ID 
    # %t = timestamp
    For example: 
    log_line_prefix = '< %u %d %r %p %t >' 
    ###### Log Hostname 
    By default only IP address is logged. To also log the hostname the following
    parameter can also be set in postgresql.conf: 
    log_hostname = on 
    Now, as the system administrator, reload the server with the new configuration: 
    # SYSTEMD SERVER ONLY 
    $ sudo systemctl reload postgresql-${PGVER?}
    # INITD SERVER ONLY 
    $ sudo service postgresql-${PGVER?} reload"

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    log_line_prefix_escapes = %w(%u %d %r %p %t)
    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end

    describe sql.query('SHOW log_hostname;', [pg_db]) do
      its('output') { should match /(on|true)/i }
    end
  end

  control "V-233593" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233594" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233595" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
      having organization-defined security label values with information in process' do
      skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
      having organization-defined security label values with information in process'
    end
  end

  control "V-233596" do
    desc "check", "To check if password encryption is enabled, as the database
    administrator (shown here as \"postgres\"), run the following SQL:
    $ psql -c \"SHOW password_encryption\" "

    desc "fix", "Set password_encryption to 'on' or 'true'"
    
    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    describe sql.query('SHOW password_encryption;', [pg_db]) do
      its('output') { should match /on|true/i }
    end

  end
  
  control "V-233597" do
    desc "check", "To list all the permissions of individual roles, as the database
    administrator (shown here as \"postgres\"), run the following SQL:
    $ psql -c \"\\du
    If any role has SUPERUSER that should not, this is a finding.
    Next, list all the permissions of databases and schemas by running the following SQL:
    $ psql -c \"\\l\"
    $ psql -c \"\\dn+\"
    If any database or schema has update (\"W\") or create (\"C\") privileges and should
    not, this is a finding."
    desc "fix", "Configure PostgreSQL to enforce access restrictions associated with
    changes to the configuration of PostgreSQL or database(s).
    Use ALTER ROLE to remove accesses from roles:
    $ psql -c \"ALTER ROLE <role_name> NOSUPERUSER\"
    Use REVOKE to remove privileges from databases and schemas:
    $ psql -c \"REVOKE ALL PRIVILEGES ON <table> FROM <role_name>;"

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    pg_superusers = input('pg_superusers')
    pg_db = input('pg_db')
    pg_owner = input('pg_owner')

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [pg_db])
    roles = roles_query.lines

    roles.each do |role|
      unless pg_superusers.include?(role)
        superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
          "WHERE r.rolname = '#{role}';"

        describe sql.query(superuser_sql, [pg_db]) do
          its('output') { should_not eq 't' }
        end
      end
    end

    authorized_owners = pg_superusers
    owners = authorized_owners.join('|')

    database_granted_privileges = 'CTc'
    database_public_privileges = 'c'
    database_acl = "^((((#{owners})=[#{database_granted_privileges}]+|"\
      "=[#{database_public_privileges}]+)\/\\w+,?)+|)\\|"
    database_acl_regex = Regexp.new(database_acl)

    schema_granted_privileges = 'UC'
    schema_public_privileges = 'U'
    schema_acl = "^((((#{owners})=[#{schema_granted_privileges}]+|"\
      "=[#{schema_public_privileges}]+)\/\\w+,?)+|)\\|"
    schema_acl_regex = Regexp.new(schema_acl)

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate AND datname != \'rdsadmin\';'
    databases_query = sql.query(databases_sql, [pg_db])
    databases = databases_query.lines

    databases.each do |database|
      datacl_sql = "SELECT pg_catalog.array_to_string(datacl, E','), datname "\
        "FROM pg_catalog.pg_database WHERE datname = '#{database}';"

      describe sql.query(datacl_sql, [pg_db]) do
        its('output') { should match database_acl_regex }
      end

      schemas_sql = "SELECT n.nspname, FROM pg_catalog.pg_namespace n "\
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
      schemas_query = sql.query(schemas_query, [database])
      # Handle connection disabled on database
      if schemas_query.methods.include?(:output)
        schemas = schemas_query.lines

        schemas.each do |schema|
          nspacl_sql = "SELECT pg_catalog.array_to_string(n.nspacl, E','), "\
            "n.nspname FROM pg_catalog.pg_namespace n "\
            "WHERE n.nspname = '#{schema}';"

          describe sql.query(nspacl_sql) do
            its('output') { should match schema_acl_regex }
          end
        end
      end
    end
  end

  control "V-233598" do
    desc "check", "First, as the database administrator, review the current
    log_line_prefix settings by running the following SQL: 
    $ sudo su - postgres 
    $ psql -c \"SHOW log_line_prefix\" 
    If log_line_prefix does not contain at least '< %t %u %d %r %p %t >', this
    is a finding. 
    Next, review the current shared_preload_libraries settings by running the
    following SQL: 
    $ psql -c \"SHOW shared_preload_libraries\" 
    If shared_preload_libraries does not contain \"pgaudit\", this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.
    Configure the database to supply additional auditing information to protect
    against a user falsely repudiating having performed organization-defined
    actions. 
    Using pgaudit PostgreSQL can be configured to audit these requests. See
    supplementary content APPENDIX-B for documentation on installing pgaudit. 
    To ensure that logging is enabled, review supplementary content APPENDIX-C for
    instructions on enabling logging. 
    Modify the configuration of audit logs to include details identifying the
    individual user: 
    First, as the database administrator (shown here as \"postgres\"), edit
    postgresql.conf: 
    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 
    Extra parameters can be added to the setting log_line_prefix to identify the
    user: 
    log_line_prefix = '< %t %u %d %r %p %t >' 
    Now, as the system administrator, reload the server with the new configuration: 
    # SYSTEMD SERVER ONLY 
    $ sudo systemctl reload postgresql-${PGVER?}
    # INITD SERVER ONLY 
    $ sudo service postgresql-${PGVER?} reload 
    Use accounts assigned to individual users. Where the application connects to
    PostgreSQL using a standard, shared account, ensure that it also captures the
    individual user identification and passes it to PostgreSQL."

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    log_line_prefix_escapes = %w(%t %u %d %p %r)

    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end

    describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
      its('output') { should include 'pgaudit' }
    end
  end

  control "V-233599" do
    describe "A manual review is required to ensure the system provides a warning to appropriate support staff when
      allocated audit record storage volume reaches 75% of maximum audit record storage capacity" do
      skip "A manual review is required to ensure the system provides a warning to appropriate support staff when
      allocated audit record storage volume reaches 75% of maximum audit record storage capacity"
    end 
  end

  control "V-233601" do
    describe "A manual review is required to ensure PostgreSQL requires users to reauthenticate when organization-defined
      circumstances or situations require reauthentication" do
      skip  "A manual review is required to ensure PostgreSQL requires users to reauthenticate when organization-defined
      circumstances or situations require reauthentication"
    end
  end

  control "V-233602" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233604" do
    desc "check", "As the database administrator (shown here as \"postgres\"),
    verify the current log_line_prefix setting:
    $ psql -c \"SHOW log_line_prefix\"

    Verify that the current settings are appropriate for the organization.

    The following is what is possible for logged information:

    # %a = application name
    # %u = user name
    # %d = database name
    # %r = remote host and port
    # %h = remote host
    # %p = process ID
    # %t = timestamp without milliseconds
    # %m = timestamp with milliseconds
    # %i = command tag
    # %e = SQL state
    # %c = session ID
    # %l = session line number
    # %s = session start timestamp
    # %v = virtual transaction ID
    # %x = transaction ID (0 if none)
    # %q = stop here in non-session processes

    If the audit record does not log events required by the organization, this is a
    finding.

    Next, verify the current settings of log_connections and log_disconnections by
    running the following SQL:

    $ psql -c \"SHOW log_connections\"
    $ psql -c \"SHOW log_disconnections\"

    If both settings are off, this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.

    To ensure that logging is enabled, review supplementary content APPENDIX-C for
    instructions on enabling logging. 

    If logging is enabled the following configurations must be made to log
    connections, date/time, username and session identifier. 

    Edit the following parameters based on the organization's needs (minimum
    requirements are as follows): 

    log_connections = on 
    log_disconnections = on 
    log_line_prefix = '< %t %u %d %p >' 

    Now, as the system administrator, reload the server with the new configuration"

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    log_line_prefix_escapes = %w(%t %u %d %p)
    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end

    describe sql.query('SHOW log_connections;', [pg_db]) do
      its('output') { should_not match /off|false/i }
    end

    describe sql.query('SHOW log_disconnections;', [pg_db]) do
      its('output') { should_not match /off|false/i }
    end
  end

  control "V-233607" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233608" do
    desc "check", "As the database administrator (usually postgres), run the
    following SQL: 
    $ psql -c \"SHOW log_line_prefix\" 
    If the query result does not contain \"%t\", this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA and PGVER
    environment variables. See supplementary content APPENDIX-F for instructions on
    configuring PGDATA and APPENDIX-H for PGVER.
    Logging must be enabled in order to capture timestamps. To ensure that logging
    is enabled, review supplementary content APPENDIX-C for instructions on
    enabling logging. 
    If logging is enabled the following configurations must be made to log events
    with timestamps: 

    Add %m to log_line_prefix to enable timestamps with milliseconds: 
    log_line_prefix = '< %t >' 
    Now, as the system administrator, reload the server with the new configuration"

    pg_ver = input('pg_version')

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    log_line_prefix_escapes = ['%t']

    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end
  end

  control "V-233609" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233610" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233612" do
    desc "check", "Review PostgreSQL settings to determine whether organizational users
    are uniquely identified and authenticated when logging on/connecting to the system.
    To list all roles in the database, as the database administrator (shown here as
    \"postgres\"), run the following SQL:
    $ psql -c \"\\du\"
    If organizational users are not uniquely identified and authenticated, this is a
    finding."

    desc "fix", "Note: The following instructions use the PGDATA environment variable.
    See supplementary content APPENDIX-F for instructions on configuring PGDATA.
    Configure PostgreSQL settings to uniquely identify and authenticate all
    organizational users who log on/connect to the system.
    To create roles, use the following SQL:
    CREATE ROLE <role_name> [OPTIONS]
    For more information on CREATE ROLE, see the official documentation:
    https://www.postgresql.org/docs/current/static/sql-createrole.html"

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
    pg_users = input('pg_users')
    pg_db = input('pg_db')

    authorized_roles = pg_users

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

    describe sql.query(roles_sql, [pg_db]) do
      its('lines.sort') { should cmp authorized_roles.sort}
    end

  end

  control "V-233613" do
    describe 'A manual review is required to ensure PostgreSQ automatically terminates a user session after
      organization-defined conditions or trigger events requiring session disconnect' do
      skip 'A manual review is required to ensure PostgreSQ automatically terminates a user session after
      organization-defined conditions or trigger events requiring session disconnect'
    end
  end

  control "V-233615" do
    describe 'A manual review is required to ensure PostgreSQL maps the PKI-authenticated identity to an associated user
      account' do 
      skip 'A manual review is required to ensure PostgreSQL maps the PKI-authenticated identity to an associated user
      account'
    end
  end

  control "V-233616" do
    describe 'A manual review is required to ensure the database contents are protected from unauthorized and unintended
      information transfer by enforcement of a data-transfer policy' do
      skip 'A manual review is required to ensure the database contents are protected from unauthorized and unintended
      information transfer by enforcement of a data-transfer policy'
    end
  end

  control "V-233617" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233618" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233619" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233620" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233621" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-233623" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-233578" do
    desc "check", "Note: The following instructions use the PGDATA environment
    variable. See supplementary content APPENDIX-F for instructions on configuring
    PGDATA.
    First, as the database administrator (shown here as \"postgres\"), check the
    current log_line_prefix setting by running the following SQL:
    $ psql -c \"SHOW log_line_prefix\"
    If log_line_prefix does not contain %t %u %d, this is a finding."

    desc "fix", "Note: The following instructions use the PGDATA environment
    variable. See supplementary content APPENDIX-F for instructions on configuring
    PGDATA.
    To check that logging is enabled, review supplementary content APPENDIX-C for
    instructions on enabling logging.
    Extra parameters can be added to the setting log_line_prefix to log application
    related information:
    # %a = application name
    # %u = user name
    # %d = database name
    # %r = remote host and port
    # %p = process ID
    # %m = timestamp with milliseconds
    # %t = timestamp without milliseconds
    # %i = command tag
    # %s = session startup
    # %e = SQL state
    For example:
    log_line_prefix = '< %t %a %u %d %r %p %i %e %s>’
    Now, as the system administrator, reload the server with the new configuration"

    pg_dba = input('pg_dba')

    pg_dba_password = input('pg_dba_password')

    pg_db = input('pg_db')

    pg_host = input('pg_host')

    sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

    log_line_prefix_escapes = %w(%t %u %d)

    log_line_prefix_escapes.each do |escape|
      describe sql.query('SHOW log_line_prefix;', [pg_db]) do
        its('output') { should include escape }
      end
    end
  end

end

