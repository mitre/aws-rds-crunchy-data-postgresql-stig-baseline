# encoding: utf-8


include_controls 'pgstigcheck-inspec' do

  control "V-72841" do

   sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    describe sql.query('SHOW port;', [attribute('pg_db')]) do
      its('output') { should cmp attribute('pg_port') }
    end

  end

  control "V-72845" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end


  control "V-72849" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
  
  control "V-72851" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    describe sql.query('SHOW client_min_messages;', [attribute('pg_db')]) do
    its('output') { should match /^error$/i }
    end
  end

  control "V-72857" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72859" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [attribute('pg_db')])
    roles = roles_query.lines

    roles.each do |role|
      unless attribute('pg_superusers').include?(role)
        superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
          "WHERE r.rolname = '#{role}';"

        describe sql.query(superuser_sql, [attribute('pg_db')]) do
          its('output') { should_not eq 't' }
        end
      end
    end

    authorized_owners = attribute('pg_superusers')
    owners = authorized_owners.join('|')

    object_granted_privileges = 'arwdDxtU'
    object_public_privileges = 'r'
    object_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
      "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
    object_acl_regex = Regexp.new(object_acl)

    objects_sql = "SELECT n.nspname, c.relname, c.relkind "\
      "FROM pg_catalog.pg_class c "\
      "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
      "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f') "\
      "AND n.nspname !~ '^pg_' AND pg_catalog.pg_table_is_visible(c.oid);"

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
    databases_query = sql.query(databases_sql, [attribute('pg_db')])
    databases = databases_query.lines

    databases.each do |database|
      rows = sql.query(objects_sql, [database])
      if rows.methods.include?(:output) # Handle connection disabled on database
        objects = rows.lines

        objects.each do |obj|
          schema, object, type = obj.split('|')
          relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
            "n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
            "AND c.relkind = '#{type}';"

          describe sql.query(relacl_sql, [database]) do
            its('output') { should match object_acl_regex }
          end
          # TODO: Add test for column acl
        end
      end
    end
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72861" do
    describe 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in transmission' do
    skip 'A manual review is required to ensure PostgreSQL associates organization-defined types of security labels
    having organization-defined security label values with information in transmission'
  end
  end

  control "V-72865" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    authorized_owners = attribute('pg_superusers')
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

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
    databases_query = sql.query(databases_sql, [attribute('pg_db')])
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
            # TODO: Add test for column acl
            tested.push(obj)
          end
        end
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

  control "V-72891" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [attribute('pg_db')])
    roles = roles_query.lines

    roles.each do |role|
      unless attribute('pg_superusers').include?(role)
        superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
          "WHERE r.rolname = '#{role}';"

        describe sql.query(superuser_sql, [attribute('pg_db')]) do
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

  control "V-72917" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72979" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    ssl_crl_file_query = sql.query('SHOW ssl_crl_file;', [attribute('pg_db')])

    describe ssl_crl_file_query do
      its('output') { should match /^\w+\.crl$/ }
    end
  end

  control "V-72983" do
    describe 'A manual review is required to ensure PostgreSQL provides audit record generation capability for
      DoD-defined auditable events within all DBMS/database components.' do
      skip 'A manual review is required to ensure PostgreSQL provides audit record generation capability for
      DoD-defined auditable events within all DBMS/database components.'
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

  control "V-73045" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))
  
    describe sql.query('SHOW log_destination;', [attribute('pg_db')]) do
      its('output') { should match /syslog/i }
    end
  end

  control "V-73049" do
    sql = postgres_session(attribute('pg_dba'), attribute('pg_dba_password'), attribute('pg_host'))

    authorized_roles = attribute('pg_users')

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

    describe sql.query(roles_sql, [attribute('pg_db')]) do
      its('lines.sort') { should cmp authorized_roles.sort }
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

  control "V-73071" do
      describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end
end