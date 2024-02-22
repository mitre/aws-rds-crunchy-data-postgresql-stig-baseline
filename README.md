# aws-rds-crunchy-data-postgresql-stig-baseline

InSpec profile to validate the secure configuration of AWS RDS hosted PostgreSQL Database, against [DISA](https://iase.disa.mil/stigs/)'s Crunchy Data PostgreSQL Security Technical Implementation Guide (STIG) Version 2, Release 2. (Applies to database versions 10, 11, 12 & 13)

## Getting Started  

It is intended and recommended that InSpec and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

### PSQL client setup

To run the PostgreSQL profile against an AWS RDS Instance, InSpec expects the psql client to be readily available on the same runner system it is installed on.
 
For example, to install the psql client on a Linux runner host:
```
sudo yum install postgresql
```
To confirm successful install of psql:
```
which psql
```
> sample output:  _/usr/bin/psql_
```
psql –-version
```		
> sample output:  *psql (PostgreSQL) 12.9*

Test psql connectivity to your instance from your runner host:
```
psql -d postgresql://<master user>:<password>@<endpoint>.amazonaws.com/postgres
```		
> *sample output:*
> 
>  *psql (12.9)*
>  
>  *SSL connection (cipher: ECDHE-RSA-AES256-GCM-SHA384, bits: 256)*
>  
>  *Type "help" for help.*
>  
>  *postgres-> \conninfo*
>  
>  *You are connected to database "postgres" as user "postgres" on host "(endpoint).us-east-1.rds.amazonaws.com" at port "5432".*
>  
>  *postgres=> \q*
>  
>  *$*

For installation of psql client on other operating systems for your runner host, visit https://www.postgresql.org/
  
## Inputs: Tailoring your scan to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).
#### *Note* Windows and Linux InSpec Runner

There are current issues with how the profiles run when using a windows or linux runner. We have accounted for this in the profile with the `windows_runner` input - which we *default* to `false` assuming a Linux based InSpec runner.

If you are using a *Windows* based inspec installation, please set the `windows_runner` input to `true` either via your `inspec.yml` file or via the cli flag via, `--input windows_runner=true`

### Example Inputs You Can Use

```yaml
# Windows or Linux Runner (default value = false)
windows_runner: false

# Description: 'Postgres database admin user (e.g., 'postgres').'
pg_dba: '<master user, e.g., postgres>'

# Description: 'Postgres database admin password (e.g., 'tesT$4329uyskdj!kjh').'
pg_dba_password: '<password>'

# Description: 'Postgres database hostname'
pg_host: '<endpoint>.amazonaws.com'

# Description: 'Postgres database name (e.g., 'postgres')'
pg_db: '<database name>'

# Description: 'Postgres database port'
pg_port: '5432'

# Description: 'Postgres users e.g., ["pg_signal_backend", "postgres", "rds_iam", "rds_pgaudit", "rds_replication", "rds_superuser", "rdsadmin", "rdsrepladmin"]'
pg_users: ["pg_signal_backend", "postgres", "rds_iam", "rds_pgaudit", "rds_replication", "rds_superuser", "rdsadmin", "rdsrepladmin"]

# Description: 'list of approved database extensions'
approved_ext: ["pgaudit"]

# Description: 'uses this list of approved postgres-related packages (e.g., postgresql-server.x86_64, postgresql-odbc.x86_64)'
approved_packages: []

# Description: 'Postgres super users (e.g., ['postgres']).'
pg_superusers: []

# Description: 'Database version' (e.g., 12.9)
pg_version: ''

# Description: 'Postgres ssl setting (e.g., 'on').'
pg_ssl: ''

# Description: 'Postgres audit log items (e.g., ['ddl','role','read','write']).'
pgaudit_log_items: []

# Description: 'Postgres audit log line items (e.g. ['%m','%u','%c']).'
pgaudit_log_line_items: []

# Description: 'Postgres replicas (e.g. ['192.168.1.3/32']).'
pg_replicas: []

# Description: 'Postgres max number of connections allowed (e.g., 100).'
pg_max_connections: 100

# Description: 'Postgres timezone (e.g., 'UTC').'
pg_timezone: 'UTC'
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/archive/master.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline
inspec archive aws-rds-crunchy-data-postgresql-stig-baseline
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd aws-rds-crunchy-data-postgresql-stig-baseline
git pull
cd ..
inspec archive aws-rds-crunchy-data-postgresql-stig-baseline --overwrite
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Alicia Sturtevant - [asturtevant](https://github.com/asturtevant)

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/issues/new).
