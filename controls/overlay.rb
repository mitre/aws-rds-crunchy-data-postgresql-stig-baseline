# encoding: utf-8


include_controls 'pgstigcheck-inspec' do

  control "V-72841" do

   sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

    describe sql.query('SHOW port;', [input('pg_db')]) do
      its('output') { should cmp input('pg_port') }
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
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

    describe sql.query('SHOW client_min_messages;', [input('pg_db')]) do
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
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

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

    authorized_owners = input('pg_superusers')
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
    databases_query = sql.query(databases_sql, [input('pg_db')])
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
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

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

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
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

  control "V-72883" do
  title "PostgreSQL must enforce discretionary access control policies, as
  defined by the data owner, over defined subjects and objects."
  desc  "Discretionary Access Control (DAC) is based on the notion that
  individual users are \"owners\" of objects and therefore have discretion over
  who should be authorized to access the object and in which mode (e.g., read or
  write). Ownership is usually acquired as a consequence of creating the object
  or via specified ownership assignment. DAC allows the owner to determine who
  will have access to objects they control. An example of DAC includes
  user-controlled table permissions.
  When discretionary access control policies are implemented, subjects are not
  constrained with regard to what actions they can take with information for
  which they have already been granted access. Thus, subjects that have been
  granted access to information are not prevented from passing (i.e., the
  subjects have the discretion to pass) the information to other subjects or
  objects.
  A subject that is constrained in its operation by Mandatory Access Control
  policies is still able to operate under the less rigorous constraints of this
  requirement. Thus, while Mandatory Access Control imposes constraints
  preventing a subject from passing information to another subject operating at
  a different sensitivity level, this requirement permits the subject to pass
  the information to any subject at the same sensitivity level.
  The policy is bounded by the information system boundary. Once the information
  is passed outside of the control of the information system, additional means
  may be required to ensure the constraints remain in effect. While the older,
  more traditional definitions of discretionary access control require i
  dentity-based access control, that limitation is not required for this use of
  discretionary access control."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000328-DB-000301"
  tag "gid": "V-72883"
  tag "rid": "SV-87535r1_rule"
  tag "stig_id": "PGS9-00-002200"
  tag "cci": ["CCI-002165"]
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "check": "Review system documentation to identify the required
  discretionary access control (DAC).
  Review the security configuration of the database and PostgreSQL. If
  applicable, review the security configuration of the application(s) using the
  database.
  If the discretionary access control defined in the documentation is not
  implemented in the security configuration, this is a finding.
  If any database objects are found to be owned by users not authorized to own
  database objects, this is a finding.
  To check the ownership of objects in the database, as the database
  administrator, run the following:
  $ sudo su - postgres
  $ psql -c \"\\dn *.*\"
  $ psql -c \"\\dt *.*\"
  $ psql -c \"\\ds *.*\"
  $ psql -c \"\\dv *.*\"
  $ psql -c \"\\df+ *.*\"
  If any role is given privileges to objects it should not have, this is a
  finding."
  tag "fix": "Implement the organization's DAC policy in the security
  configuration of the database and PostgreSQL, and, if applicable, the security
  configuration of the application(s) using the database.
  To GRANT privileges to roles, as the database administrator (shown here as
  \"postgres\"), run statements like the following examples:
  $ sudo su - postgres
  $ psql -c \"CREATE SCHEMA test\"
  $ psql -c \"GRANT CREATE ON SCHEMA test TO bob\"
  $ psql -c \"CREATE TABLE test.test_table(id INT)\"
  $ psql -c \"GRANT SELECT ON TABLE test.test_table TO bob\"
  To REVOKE privileges to roles, as the database administrator (shown here as
  \"postgres\"), run statements like the following examples:
  $ psql -c \"REVOKE SELECT ON TABLE test.test_table FROM bob\"
  $ psql -c \"REVOKE CREATE ON SCHEMA test FROM bob\""

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

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
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}';"
    else
      schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_namespace n "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
        "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
        "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
        "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
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
          "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' "
          "AND n.nspname !~ '^pg_toast';"
      else
        objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
          "WHERE c.relkind IN ('#{type}','s','') "\
          "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
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

  control "V-72891" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

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
    title "Database objects (including but not limited to tables, indexes,
    storage, trigger procedures, functions, links to software external to
    PostgreSQL, etc.) must be owned by database/DBMS principals authorized for
    ownership."
    desc  "Within the database, object ownership implies full privileges to the
    owned object, including the privilege to assign access to the owned objects
    to other subjects. Database functions and procedures can be coded using
    definer's rights. This allows anyone who utilizes the object to perform the
    actions if they were the owner. If not properly managed, this can lead to
    privileged actions being taken by unauthorized individuals.
    Conversely, if critical tables or other objects rely on unauthorized owner
    accounts, these objects may be lost when an account is removed."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000133-DB-000200"
    tag "gid": "V-72897"
    tag "rid": "SV-87549r1_rule"
    tag "stig_id": "PGS9-00-003100"
    tag "cci": ["CCI-001499"]
    tag "nist": ["CM-5 (6)", "Rev_4"]
    tag "check": "Review system documentation to identify accounts authorized to
    own database objects. Review accounts that own objects in the database(s).
    If any database objects are found to be owned by users not authorized to own
    database objects, this is a finding.
    To check the ownership of objects in the database, as the database
    administrator, run the following SQL:
    $ sudo su - postgres
    $ psql -x -c \"\\dn *.*\"
    $ psql -x -c \"\\dt *.*\"
    $ psql -x -c \"\\ds *.*\"
    $ psql -x -c \"\\dv *.*\"
    $ psql -x -c \"\\df+ *.*\"
    If any object is not owned by an authorized role for ownership, this is a
    finding."
    tag "fix": "Assign ownership of authorized objects to authorized object owner
    accounts.
    #### Schema Owner
    To create a schema owned by the user bob, run the following SQL:
    $ sudo su - postgres
    $ psql -c \"CREATE SCHEMA test AUTHORIZATION bob
    To alter the ownership of an existing object to be owned by the user bob,
    run the following SQL:
    $ sudo su - postgres
    $ psql -c \"ALTER SCHEMA test OWNER TO bob\""

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))
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
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}';"
      else
        schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_namespace n "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
          "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
        functions_sql = "SELECT n.nspname, p.proname, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) "\
          "FROM pg_catalog.pg_proc p "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
          "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
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
            "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' "
            "AND n.nspname !~ '^pg_toast';"
        else
          objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
            "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
            "WHERE c.relkind IN ('#{type}','s','') "\
            "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
            "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
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
    collaboration with the application developers. It is recognized that in
    many cases, the database administrator (DBA) is organizationally separate
    from the application developers, and may have limited, if any, access to
    source code. Nevertheless, protections of this type are so important to the
    secure operation of databases that they must not be ignored. At a minimum,
    the DBA must attempt to obtain assurances from the development organization
    that this issue has been addressed, and must document what has been discovered."
    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000342-DB-000302"
    tag "gid": "V-72905"
    tag "rid": "SV-87557r1_rule"
    tag "stig_id": "PGS9-00-003600"
    tag "cci": ["CCI-002233"]
    tag "nist": ["AC-6 (8)", "Rev_4"]
    tag "check": "Functions in PostgreSQL can be created with the SECURITY
    DEFINER option. When SECURITY DEFINER functions are executed by a user, said
    function is run with the privileges of the user who created it.
    To list all functions that have SECURITY DEFINER, as, the database
    administrator (shown here as \"postgres\"), run the following SQL:
    $ sudo su - postgres
    $ psql -c \"SELECT nspname, proname, proargtypes, prosecdef, rolname,
    proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN
    pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;\"
    In the query results, a prosecdef value of \"t\" on a row indicates that that
    function uses privilege elevation.
    If elevation of PostgreSQL privileges is utilized but not documented, this is
    a finding.
    If elevation of PostgreSQL privileges is documented, but not implemented as
    described in the documentation, this is a finding.
    If the privilege-elevation logic can be invoked in ways other than intended,
    or in contexts other than intended, or by subjects/principals other than
    intended, this is a finding."
    tag "fix": "Determine where, when, how, and by what principals/subjects
    elevated privilege is needed.
    To change a SECURITY DEFINER function to SECURITY INVOKER, as the database
    administrator (shown here as \"postgres\"), run the following SQL:\
    $ sudo su - postgres
    $ psql -c \"ALTER FUNCTION <function_name> SECURITY INVOKER;\""

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

    security_definer_sql = "SELECT nspname, proname, prosecdef "\
      "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "\
      "JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef = 't';"

    databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '';"
    databases_query = sql.query(databases_sql, [input('pg_db')])
    databases = databases_query.lines

    databases.each do |database|
      connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
        "accepting connections"
      connection_error_regex = Regexp.new(connection_error)

      sql_result=sql.query(security_definer_sql, [database])

      if sql_result.empty?
        describe 'There are no database functions that were created with the SECURITY
          DEFINER option' do
          skip 'There are no database functions that were created with the SECURITY
          DEFINER option'
        end
      end

      if !sql_result.empty?
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

  control "V-72917" do
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system in which the postgres database is running on'
    end
  end

  control "V-72979" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

    ssl_crl_file_query = sql.query('SHOW ssl_crl_file;', [input('pg_db')])

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

  control "V-72999" do

    title "PostgreSQL must separate user functionality (including user interface
  services) from database management functionality."
    desc  "Information system management functionality includes functions necessary to
  administer databases, network components, workstations, or servers and typically
  requires privileged user access.
  The separation of user functionality from information system management
  functionality is either physical or logical and is accomplished by using different
  computers, different central processing units, different instances of the operating
  system, different network addresses, combinations of these methods, or other
  methods, as appropriate.
  An example of this type of separation is observed in web administrative interfaces
  that use separate authentication methods for users of any other information system
  resources.
  This may include isolating the administrative interface on a different domain and
  with additional access controls.
  If administrative functionality or information regarding PostgreSQL management is
  presented on an interface available for users, information on DBMS settings may be
  inadvertently made available to the user."

    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000211-DB-000122"
    tag "gid": "V-72999"
    tag "rid": "SV-87651r1_rule"
    tag "stig_id": "PGS9-00-008500"
    tag "cci": ["CCI-001082"]
    tag "nist": ["SC-2", "Rev_4"]

    tag "check": "Check PostgreSQL settings and vendor documentation to verify that
  administrative functionality is separate from user functionality.
  As the database administrator (shown here as \"postgres\"), list all roles and
  permissions for the database:
  $ sudo su - postgres
  $ psql -c \"\\du\"
  If any non-administrative role has the attribute \"Superuser\", \"Create role\",
  \"Create DB\" or \"Bypass RLS\", this is a finding.
  If administrator and general user functionality are not separated either physically
  or logically, this is a finding."
    tag "fix": "Configure PostgreSQL to separate database administration and general
  user functionality.
  Do not grant superuser, create role, create db or bypass rls role attributes to
  users that do not require it.
  To remove privileges, see the following example:
  ALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;"

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

    pg_superusers = input('pg_superusers')
    pg_db = input('pg_db')
    pg_owner = input('pg_owner')

    privileges = %w(rolcreatedb rolcreaterole rolsuper)
    
    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
    roles_query = sql.query(roles_sql, [pg_db])
    roles = roles_query.lines

    roles.each do |role|
      unless pg_superusers.include?(role)
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

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))

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

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
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

  control "V-73045" do
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))
  
    describe sql.query('SHOW log_destination;', [input('pg_db')]) do
      its('output') { should match /syslog/i }
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

    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'))
    pg_users = input('pg_users')
    pg_db = input('pg_db')

    authorized_roles = pg_users

    roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

    describe sql.query(roles_sql, [pg_db]) do
      its('lines') { should cmp authorized_roles}
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