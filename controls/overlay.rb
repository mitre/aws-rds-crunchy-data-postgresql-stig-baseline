# encoding: utf-8

include_controls 'pgstigcheck-inspec' do

  control "V-72841" do

   sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    describe sql.query('SHOW port;', [input('pg_db')]) do
      its('output') { should eq input('pg_port') }
    end

  end

  control "V-72843" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72845" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72847" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72849" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
  
  control "V-72851" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    describe sql.query('SHOW client_min_messages;', [input('pg_db')]) do
      its('output') { should match /^error$/i }
    end
  end

  control "V-72853" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72855" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72857" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
  
  control 'V-72859' do
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
      
  control "V-72861" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in transmission' do
      skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
      having organization-defined security label values with information in transmission'
    end
  end

  control 'V-72865' do
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

  control "V-72869" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in storage' do
    skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in storage'
    end
  end

  control "V-72871" do
    describe 'A manual review is required to ensure PostgreSQL checks the validity of all data inputs except those
    specifically identified by the organization' do
    skip 'A manual review is required to ensure PostgreSQL checks the validity of all data inputs except those
    specifically identified by the organization'
    end
  end

  control "V-72873" do
    describe 'A manual review is require to ensure PostgreSQL and associated applications reserve the use of dynamic
    code execution for situations that require it.' do
    skip 'A manual review is require to ensure PostgreSQL and associated applications reserve the use of dynamic
    code execution for situations that require it.'
    end 
  end

  control "V-72875" do
    describe 'PostgreSQL and associated applications, when making use of dynamic code
    execution, must scan input data for invalid values that may indicate a code injection attack' do
    skip 'PostgreSQL and associated applications, when making use of dynamic code
    execution, must scan input data for invalid values that may indicate a code injection attack'
    end
  end

  control "V-72877" do
    describe 'A manual review is required to ensure PostgreSQL allocates audit record storage capacity in accordance
    with organization-defined audit record storage requirements' do
    skip 'A manual review is required to ensure PostgreSQL allocates audit record storage capacity in accordance
    with organization-defined audit record storage requirements'
    end
  end

  control "V-72883" do
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

control "V-72885" do
  describe 'Requires manual review of the RDS audit log system at this time.' do
    skip 'Requires manual review of the RDS audit log system at this time.'
  end
end

control "V-72889" do
  describe 'Requires manual review of the RDS audit log system at this time.' do
    skip 'Requires manual review of the RDS audit log system at this time.'
  end
end

  control "V-72891" do
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

  control "V-72893" do
    describe 'A manual review is required to ensure PostgreSQL provides an immediate real-time alert to appropriate
      support staff of all audit failure events requiring real-time alerts' do
      skip 'A manual review is required to ensure PostgreSQL provides an immediate real-time alert to appropriate
      support staff of all audit failure events requiring real-time alerts'
    end
  end

  control "V-72897" do
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


  control "V-72899" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72901" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72903" do
    describe 'A manual review is required to ensure PostgreSQL includes additional, more detailed, organization-defined
      information in the audit records for audit events identified by type,
      location, or subject' do
      skip 'A manual review is required to ensure PostgreSQL includes additional, more detailed, organization-defined
      information in the audit records for audit events identified by type,
      location, or subject'
    end
  end

control "V-72905" do
  title "Execution of software modules (to include functions and trigger
  procedures) with elevated privileges must be restricted to necessary cases
  only."
  desc  "In certain situations, to provide required functionality, PostgreSQL
  needs to execute internal logic (stored procedures, functions, triggers, etc.)
  and/or external code modules with elevated privileges. However, if the
  privileges required for execution are at a higher level than the privileges
  assigned to organizational users invoking the functionality
  applications/programs, those users are indirectly provided with greater
  privileges than assigned by organizations.
      Privilege elevation must be utilized only where necessary and protected
  from misuse.
      This calls for inspection of application source code, which will require
  collaboration with the application developers. It is recognized that in many
  cases, the database administrator (DBA) is organizationally separate from the
  application developers, and may have limited, if any, access to source code.
  Nevertheless, protections of this type are so important to the secure operation
  of databases that they must not be ignored. At a minimum, the DBA must attempt
  to obtain assurances from the development organization that this issue has been
  addressed, and must document what has been discovered."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000342-DB-000302"
  tag "gid": "V-72905"
  tag "rid": "SV-87557r2_rule"
  tag "stig_id": "PGS9-00-003600"
  tag "fix_id": "F-79347r2_fix"
  tag "cci": ["CCI-002233"]
  tag "nist": ["AC-6 (8)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
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

  desc "fix", "Determine where, when, how, and by what principals/subjects
  elevated privilege is needed.  
  To change a SECURITY DEFINER function to SECURITY INVOKER, as the database
  administrator (shown here as \"postgres\"), run the following SQL: 
  $ sudo su - postgres 
  $ psql -c \"ALTER FUNCTION <function_name> SECURITY INVOKER\""
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

  control "V-72907" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72909" do
    describe 'Requires manual review of the use of a centralized logging solution at this time.' do
      skip 'Requires manual review of the use of a centralized logging solution at this time.'
    end
  end

  control "V-72911" do
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

  control "V-72913" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72915" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72917" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72919" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72921" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72923" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72925" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72927" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72929" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72931" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72933" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72939" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72941" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72945" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72947" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72949" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72951" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72955" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72957" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72959" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72961" do
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

  control "V-72963" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72965" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72969" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72971" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72973" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72975" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72977" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-72979" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages this capability' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages this capability'
    end
  end

  control "V-72983" do
    describe 'A manual review is required to ensure PostgreSQL provides audit record generation capability for
      DoD-defined auditable events within all DBMS/database components.' do
      skip 'A manual review is required to ensure PostgreSQL provides audit record generation capability for
      DoD-defined auditable events within all DBMS/database components.'
    end
  end

  control "V-72985" do
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

  control "V-72987" do
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

  control "V-72989" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end


  control "V-72993" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72999" do
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

  control "V-73009" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73011" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73013" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
      having organization-defined security label values with information in process' do
      skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
      having organization-defined security label values with information in process'
    end
  end

  
  control "V-73017" do
    title "PostgreSQL must enforce access restrictions associated with changes to the
    configuration of PostgreSQL or database(s)."
    desc  "Failure to provide logical access restrictions associated with changes to
    configuration may have significant effects on the overall security of the system.
    When dealing with access restrictions pertaining to change control, it should be
    noted that any changes to the hardware, software, and/or firmware components of the
    information system can potentially have significant effects on the overall security
    of the system.
    Accordingly, only qualified and authorized individuals should be allowed to obtain
    access to system components for the purposes of initiating changes, including
    upgrades and modifications."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000380-DB-000360"
    tag "gid": "V-73017"
    tag "rid": "SV-87669r1_rule"
    tag "stig_id": "PGS9-00-009600"
    tag "cci": ["CCI-001813"]
    tag "nist": ["CM-5 (1)", "Rev_4"]
    tag "check": "To list all the permissions of individual roles, as the database
    administrator (shown here as \"postgres\"), run the following SQL:
    $ sudo su - postgres
    $ psql -c \"\\du
    If any role has SUPERUSER that should not, this is a finding.
    Next, list all the permissions of databases and schemas by running the following SQL:
    $ sudo su - postgres
    $ psql -c \"\\l\"
    $ psql -c \"\\dn+\"
    If any database or schema has update (\"W\") or create (\"C\") privileges and should
    not, this is a finding."
    tag "fix": "Configure PostgreSQL to enforce access restrictions associated with
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

  control "V-73023" do
    describe "A manual review is required to ensure the system provides a warning to appropriate support staff when
      allocated audit record storage volume reaches 75% of maximum audit record storage capacity" do
      skip "A manual review is required to ensure the system provides a warning to appropriate support staff when
      allocated audit record storage volume reaches 75% of maximum audit record storage capacity"
    end 
  end

  control "V-73027" do
    describe "A manual review is required to ensure PostgreSQL requires users to reauthenticate when organization-defined
      circumstances or situations require reauthentication" do
      skip  "A manual review is required to ensure PostgreSQL requires users to reauthenticate when organization-defined
      circumstances or situations require reauthentication"
    end
  end

  control "V-73029" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73039" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-73043" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73045" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-73049" do
    title "PostgreSQL must uniquely identify and authenticate organizational users (or
    processes acting on behalf of organizational users)."
    desc  "To assure accountability and prevent unauthenticated access, organizational
    users must be identified and authenticated to prevent potential misuse and
    compromise of the system.
    Organizational users include organizational employees or individuals the
    organization deems to have cmpuivalent status of employees (e.g., contractors).
    Organizational users (and any processes acting on behalf of users) must be uniquely
    identified and authenticated for all accesses, except the following:
    (i) Accesses explicitly identified and documented by the organization. Organizations
    document specific user actions that can be performed on the information system
    without identification or authentication; and
    (ii) Accesses that occur through authorized use of group authenticators without
    individual authentication. Organizations may rcmpuire unique identification of
    individuals using shared accounts, for detailed accountability of individual
    activity."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000148-DB-000103"
    tag "gid": "V-73049"
    tag "rid": "SV-87701r1_rule"
    tag "stig_id": "PGS9-00-011500"
    tag "cci": ["CCI-000764"]
    tag "nist": ["IA-2", "Rev_4"]
    tag "check": "Review PostgreSQL settings to determine whether organizational users
    are uniquely identified and authenticated when logging on/connecting to the system.
    To list all roles in the database, as the database administrator (shown here as
    \"postgres\"), run the following SQL:
    $ sudo su - postgres
    $ psql -c \"\\du\"
    If organizational users are not uniquely identified and authenticated, this is a
    finding.
    Next, as the database administrator (shown here as \"postgres\"), verify the current
    pg_hba.conf authentication settings:
    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_hba.conf
    If every role does not have unique authentication rcmpuirements, this is a finding.
    If accounts are determined to be shared, determine if individuals are first
    individually authenticated. If individuals are not individually authenticated before
    using the shared account, this is a finding."

    tag "fix": "Note: The following instructions use the PGDATA environment variable.
    See supplementary content APPENDIX-F for instructions on configuring PGDATA.
    Configure PostgreSQL settings to uniquely identify and authenticate all
    organizational users who log on/connect to the system.
    To create roles, use the following SQL:
    CREATE ROLE <role_name> [OPTIONS]
    For more information on CREATE ROLE, see the official documentation:
    https://www.postgresql.org/docs/current/static/sql-createrole.html
    For each role created, the database administrator can specify database
    authentication by editing pg_hba.conf:
    $ sudo su - postgres
    $ vi ${PGDATA?}/pg_hba.conf
    An example pg_hba entry looks like this:
    # TYPE DATABASE USER ADDRESS METHOD
    host test_db bob 192.168.0.0/16 md5
    For more information on pg_hba.conf, see the official documentation:
    https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html"

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
    pg_users = input('pg_users')
    pg_db = input('pg_db')

    authorized_roles = pg_users

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

    describe sql.query(roles_sql, [pg_db]) do
      its('lines.sort') { should cmp authorized_roles.sort}
    end

  end

  control "V-73051" do
    describe 'A manual review is required to ensure PostgreSQ automatically terminates a user session after
      organization-defined conditions or trigger events requiring session disconnect' do
      skip 'A manual review is required to ensure PostgreSQ automatically terminates a user session after
      organization-defined conditions or trigger events requiring session disconnect'
    end
  end

  control "V-73055" do
    describe 'A manual review is required to ensure PostgreSQL maps the PKI-authenticated identity to an associated user
      account' do 
      skip 'A manual review is required to ensure PostgreSQL maps the PKI-authenticated identity to an associated user
      account'
    end
  end

  control "V-73057" do
    describe 'A manual review is required to ensure the database contents are protected from unauthorized and unintended
      information transfer by enforcement of a data-transfer policy' do
      skip 'A manual review is required to ensure the database contents are protected from unauthorized and unintended
      information transfer by enforcement of a data-transfer policy'
    end
  end

  control "V-73059" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73061" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73063" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-73065" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-73067" do
    describe 'Requires manual review of the RDS audit log system at this time.' do
      skip 'Requires manual review of the RDS audit log system at this time.'
    end
  end

  control "V-73071" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
end
