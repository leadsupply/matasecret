<?php

namespace Tests\Feature\Console\Commands;

use Dotenv\Dotenv;
use Illuminate\Contracts\Process\ProcessResult;
use Illuminate\Process\PendingProcess;
use Illuminate\Redis\Connections\Connection;
use Illuminate\Support\Composer;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;
use Illuminate\Testing\PendingCommand;
use Mockery;
use RedisException;
use Tests\TestCase;

class SetupCommandTest extends TestCase
{
    private string $environmentDirectory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->environmentDirectory = sys_get_temp_dir().'/matasecret-setup-'.Str::random(8);
        File::ensureDirectoryExists($this->environmentDirectory);
        File::copy(base_path('env.base'), $this->environmentDirectory.'/env.base');
        $this->app->useEnvironmentPath($this->environmentDirectory);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->environmentDirectory);

        parent::tearDown();
    }

    public function test_frankenphp_with_its_own_certificate_installs_octane_and_builds_for_production(): void
    {
        $this->composer();

        $this->artisan('setup')
            ->expectsQuestion('Which web server will run MataSecret?', 'frankenphp')
            ->expectsConfirmation('Should FrankenPHP obtain its own TLS certificate?', 'yes')
            ->expectsQuestion('Domain', 'Secrets.Example.com')
            ->expectsQuestion('HTTPS port', '443')
            ->expectsQuestion('Where should secrets be stored?', 'apcu')
            ->expectsQuestion('Which provider will people sign in with?', 'github')
            ->expectsQuestion('GitHub client ID', 'github-client-id')
            ->expectsQuestion('GitHub client secret', 'github-client-secret')
            ->expectsQuestion('Email domains allowed to sign in and receive secret links', 'example.com')
            ->expectsQuestion('How should MataSecret send email?', 'none')
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('gith••••••')
            ->doesntExpectOutputToContain('github-client-secret')
            ->expectsOutputToContain('https://secrets.example.com/auth/callback')
            ->expectsOutputToContain('Development dependencies will be removed (composer install --no-dev)')
            ->expectsOutputToContain('php artisan octane:start --server=frankenphp --https --http-redirect')
            ->assertSuccessful();

        $this->assertRan(['composer', 'require', 'laravel/octane', '--no-scripts', '--no-interaction']);
        $this->assertComposerDidntRun('remove');
        $this->assertRan(['composer', 'install', '--no-dev', '--optimize-autoloader', '--no-interaction']);
        $this->assertRan(['pnpm', 'install']);
        $this->assertRan(['pnpm', 'run', 'build']);

        $environment = $this->writtenEnvironment();
        $expected = [
            'APP_NAME' => 'MataSecret',
            'APP_ENV' => 'production',
            'APP_DEBUG' => 'false',
            'APP_URL' => 'https://secrets.example.com',
            'LOG_LEVEL' => 'warning',
            'SESSION_SECURE_COOKIE' => 'true',
            'OCTANE_SERVER' => 'frankenphp',
            'OCTANE_HOST' => 'secrets.example.com',
            'OCTANE_PORT' => '443',
            'OCTANE_HTTPS' => 'true',
            'CACHE_STORE' => 'apc',
            'SECRETS_STORE' => 'apcu',
            'AUTH_PROVIDER' => 'github',
            'AUTH_CLIENT_ID' => 'github-client-id',
            'AUTH_CLIENT_SECRET' => 'github-client-secret',
            'AUTH_ALLOWED_DOMAINS' => 'example.com',
            'MAIL_MAILER' => 'log',
            'SECRETS_EMAIL_LINKS' => 'false',
        ];
        $written = array_intersect_key($environment, $expected);
        ksort($expected);
        ksort($written);
        $this->assertSame($expected, $written);
        $this->assertArrayNotHasKey('TRUSTED_PROXIES', $environment);
        $this->assertArrayNotHasKey('GOOGLE_CLIENT_ID', $environment);
        $this->assertSame(32, strlen((string) base64_decode(Str::after($environment['APP_KEY'], 'base64:'), true)));
        $this->assertSame(0640, fileperms($this->environmentDirectory.'/.env') & 0777);
    }

    public function test_frankenphp_behind_a_reverse_proxy_listens_locally_and_trusts_the_proxy(): void
    {
        $this->composer();

        $this->artisan('setup')
            ->expectsQuestion('Which web server will run MataSecret?', 'frankenphp')
            ->expectsConfirmation('Should FrankenPHP obtain its own TLS certificate?', 'no')
            ->expectsQuestion('Public domain', 'secrets.example.com')
            ->expectsQuestion('Port FrankenPHP listens on', '8000')
            ->expectsQuestion('Address FrankenPHP listens on', '127.0.0.1')
            ->expectsQuestion('Trusted proxy addresses', '10.0.0.0/8, 127.0.0.1')
            ->expectsQuestion('Where should secrets be stored?', 'shmop')
            ->expectsQuestion('Which provider will people sign in with?', 'google')
            ->expectsQuestion('Google Workspace client ID', 'google-client-id')
            ->expectsQuestion('Google Workspace client secret', 'google-client-secret')
            ->expectsQuestion('Email domains allowed to sign in and receive secret links', 'example.com')
            ->expectsQuestion('How should MataSecret send email?', 'smtp')
            ->expectsQuestion('SMTP host', 'smtp.example.com')
            ->expectsQuestion('SMTP port', '587')
            ->expectsQuestion('SMTP encryption', 'smtp')
            ->expectsQuestion('SMTP username', 'mailer')
            ->expectsQuestion('SMTP password', 'p@ss word$1')
            ->expectsQuestion('From address', 'no-reply@example.com')
            ->expectsQuestion('From name', 'MataSecret Team')
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('Point your reverse proxy at http://127.0.0.1:8000.')
            ->doesntExpectOutputToContain('--https')
            ->assertSuccessful();

        $this->assertRan(['composer', 'require', 'laravel/octane', '--no-scripts', '--no-interaction']);

        $environment = $this->writtenEnvironment();
        $this->assertSame('https://secrets.example.com', $environment['APP_URL']);
        $this->assertSame('127.0.0.1', $environment['OCTANE_HOST']);
        $this->assertSame('8000', $environment['OCTANE_PORT']);
        $this->assertSame('10.0.0.0/8,127.0.0.1', $environment['TRUSTED_PROXIES']);
        $this->assertSame('apc', $environment['CACHE_STORE']);
        $this->assertSame('shmop', $environment['SECRETS_STORE']);
        $this->assertSame('smtp', $environment['MAIL_MAILER']);
        $this->assertSame('smtp.example.com', $environment['MAIL_HOST']);
        $this->assertSame('p@ss word$1', $environment['MAIL_PASSWORD']);
        $this->assertSame('MataSecret Team', $environment['MAIL_FROM_NAME']);
        $this->assertSame('true', $environment['SECRETS_EMAIL_LINKS']);
    }

    public function test_okta_with_redis_and_postmark_installs_their_packages(): void
    {
        $this->composer();
        $this->redisAnswers();

        $this->artisan('setup')
            ->expectsQuestion('Which web server will run MataSecret?', 'traditional')
            ->expectsQuestion('Domain', 'secrets.example.com')
            ->expectsQuestion('HTTPS port', '8443')
            ->expectsQuestion('Where should secrets be stored?', 'redis')
            ->expectsQuestion('Redis host', '127.0.0.1')
            ->expectsQuestion('Redis port', '6379')
            ->expectsQuestion('Redis username', '')
            ->expectsQuestion('Redis password', 'redis-password')
            ->expectsQuestion('Redis database for secrets', '2')
            ->expectsQuestion('Which provider will people sign in with?', 'okta')
            ->expectsQuestion('Okta client ID', 'okta-client-id')
            ->expectsQuestion('Okta client secret', 'okta-client-secret')
            ->expectsQuestion('Okta organization URL', 'https://acme.okta.com/')
            ->expectsQuestion('Okta authorization server ID', 'default')
            ->expectsQuestion('Email domains allowed to sign in and receive secret links', 'example.com, Example.org')
            ->expectsQuestion('How should MataSecret send email?', 'postmark')
            ->expectsQuestion('Postmark server token', 'postmark-token')
            ->expectsQuestion('Postmark message stream', '')
            ->expectsQuestion('From address', 'no-reply@example.com')
            ->expectsQuestion('From name', 'MataSecret')
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('Redis answered.')
            ->expectsOutputToContain('https://secrets.example.com:8443/auth/callback')
            ->assertSuccessful();

        $this->assertRan(['composer', 'require', 'socialiteproviders/okta', 'symfony/postmark-mailer', 'symfony/http-client', '--no-scripts', '--no-interaction']);
        $this->assertComposerDidntRun('remove');

        $environment = $this->writtenEnvironment();
        $this->assertSame('https://secrets.example.com:8443', $environment['APP_URL']);
        $this->assertSame([], array_filter(array_keys($environment), fn (string $key): bool => str_starts_with($key, 'OCTANE_')));
        $this->assertSame('redis', $environment['CACHE_STORE']);
        $this->assertSame('redis', $environment['SECRETS_STORE']);
        $this->assertSame('redis-password', $environment['REDIS_PASSWORD']);
        $this->assertSame('2', $environment['REDIS_SECRETS_DB']);
        $this->assertArrayNotHasKey('REDIS_USERNAME', $environment);
        $this->assertSame('okta', $environment['AUTH_PROVIDER']);
        $this->assertSame('https://acme.okta.com', $environment['AUTH_BASE_URL']);
        $this->assertSame('default', $environment['AUTH_AUTH_SERVER_ID']);
        $this->assertSame('example.com,example.org', $environment['AUTH_ALLOWED_DOMAINS']);
        $this->assertSame('postmark', $environment['MAIL_MAILER']);
        $this->assertSame('postmark-token', $environment['POSTMARK_API_KEY']);
        $this->assertArrayNotHasKey('POSTMARK_MESSAGE_STREAM_ID', $environment);
    }

    public function test_continues_with_the_redis_details_when_redis_does_not_answer_and_the_user_moves_on(): void
    {
        $this->composer();
        $this->redisAnswers(responds: false);

        $this->artisan('setup')
            ->expectsQuestion('Which web server will run MataSecret?', 'traditional')
            ->expectsQuestion('Domain', 'secrets.example.com')
            ->expectsQuestion('HTTPS port', '443')
            ->expectsQuestion('Where should secrets be stored?', 'redis')
            ->expectsQuestion('Redis host', 'redis.internal')
            ->expectsQuestion('Redis port', '6380')
            ->expectsQuestion('Redis username', 'matasecret')
            ->expectsQuestion('Redis password', '')
            ->expectsQuestion('Redis database for secrets', '3')
            ->expectsConfirmation('Redis did not answer. Enter the connection details again?', 'no')
            ->expectsQuestion('Which provider will people sign in with?', 'github')
            ->expectsQuestion('GitHub client ID', 'github-client-id')
            ->expectsQuestion('GitHub client secret', 'github-client-secret')
            ->expectsQuestion('Email domains allowed to sign in and receive secret links', 'example.com')
            ->expectsQuestion('How should MataSecret send email?', 'none')
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->assertSuccessful();

        $environment = $this->writtenEnvironment();
        $this->assertSame('redis.internal', $environment['REDIS_HOST']);
        $this->assertSame('6380', $environment['REDIS_PORT']);
        $this->assertSame('matasecret', $environment['REDIS_USERNAME']);
        $this->assertSame('null', $environment['REDIS_PASSWORD']);
        $this->assertSame('3', $environment['REDIS_SECRETS_DB']);
    }

    public function test_removes_packages_from_a_previous_setup_that_are_no_longer_needed(): void
    {
        $this->composer(installed: ['laravel/octane', 'socialiteproviders/okta', 'symfony/postmark-mailer', 'symfony/http-client']);

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->assertSuccessful();

        $this->assertRan(['composer', 'remove', 'laravel/octane', 'socialiteproviders/okta', 'symfony/http-client', 'symfony/postmark-mailer', '--no-scripts', '--no-interaction']);
        $this->assertComposerDidntRun('require');

        $this->assertSame('gitlab', $this->writtenEnvironment()['AUTH_PROVIDER']);
    }

    public function test_falls_back_to_npm_when_pnpm_is_not_installed(): void
    {
        $this->composer(processes: ['command -v pnpm' => Process::result(exitCode: 1)]);

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->assertSuccessful();

        $this->assertRan(['npm', 'install']);
        $this->assertRan(['npm', 'run', 'build']);
        Process::assertDidntRun(fn (PendingProcess $process): bool => $process->command === ['pnpm', 'install']);
    }

    public function test_failed_production_install_stops_before_building_the_frontend(): void
    {
        $this->composer(processes: ['*--no-dev*' => Process::result(exitCode: 1)]);

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('composer install --no-dev failed. .env is already written')
            ->doesntExpectOutputToContain('MataSecret is configured.')
            ->assertFailed();

        $this->assertSame('gitlab', $this->writtenEnvironment()['AUTH_PROVIDER']);
        Process::assertDidntRun(fn (PendingProcess $process): bool => $process->command === ['pnpm', 'install']);
    }

    public function test_failed_frontend_build_reports_the_command_to_run_again(): void
    {
        $this->composer(processes: ["*'run' 'build'*" => Process::result(exitCode: 1)]);

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('The frontend build failed. .env is already written: fix the error above, then run pnpm install && pnpm run build.')
            ->doesntExpectOutputToContain('MataSecret is configured.')
            ->assertFailed();
    }

    public function test_warns_when_the_provider_does_not_verify_email_addresses(): void
    {
        $this->composer();

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'no')
            ->expectsOutputToContain('GitLab does not say whether an email address is verified')
            ->assertFailed();
    }

    public function test_declining_the_summary_changes_nothing(): void
    {
        $this->composer();

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'no')
            ->expectsOutputToContain('Setup cancelled. Nothing was changed.')
            ->assertFailed();

        Process::assertNothingRan();

        $this->assertFileDoesNotExist($this->environmentDirectory.'/.env');
    }

    public function test_composer_failure_leaves_the_environment_untouched(): void
    {
        $this->composer(processes: ["*'require'*" => Process::result(exitCode: 1)]);
        $composerJson = File::get(base_path('composer.json'));

        $this->artisan('setup')
            ->expectsQuestion('Which web server will run MataSecret?', 'traditional')
            ->expectsQuestion('Domain', 'secrets.example.com')
            ->expectsQuestion('HTTPS port', '443')
            ->expectsQuestion('Where should secrets be stored?', 'apcu')
            ->expectsQuestion('Which provider will people sign in with?', 'zendesk')
            ->expectsQuestion('Zendesk client ID', 'zendesk-client-id')
            ->expectsQuestion('Zendesk client secret', 'zendesk-client-secret')
            ->expectsQuestion('Zendesk subdomain', 'acme')
            ->expectsQuestion('Email domains allowed to sign in and receive secret links', 'example.com')
            ->expectsQuestion('How should MataSecret send email?', 'none')
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('Composer failed.')
            ->assertFailed();

        $this->assertFileDoesNotExist($this->environmentDirectory.'/.env');
        $this->assertSame($composerJson, File::get(base_path('composer.json')));
        $this->assertComposerDidntRun('install');
    }

    public function test_existing_environment_is_backed_up_with_its_permissions(): void
    {
        $this->composer();
        $this->travelTo('2026-11-12 10:30:00');
        File::put($this->environmentDirectory.'/.env', "APP_KEY=base64:old\n");
        chmod($this->environmentDirectory.'/.env', 0600);

        $this->runWithGitLabAndNoMailer()
            ->expectsConfirmation('Apply this configuration?', 'yes')
            ->expectsOutputToContain('The current .env will be backed up and replaced.')
            ->assertSuccessful();

        $backup = $this->environmentDirectory.'/.env.backup-20261112103000';
        $this->assertSame("APP_KEY=base64:old\n", File::get($backup));
        $this->assertSame(0600, fileperms($backup) & 0777);
        $this->assertSame(0600, fileperms($this->environmentDirectory.'/.env') & 0777);
        $this->assertNotSame('base64:old', $this->writtenEnvironment()['APP_KEY']);
    }

    public function test_stops_before_asking_anything_when_env_base_is_missing(): void
    {
        $this->composer();
        File::delete($this->environmentDirectory.'/env.base');

        $this->artisan('setup')
            ->expectsOutputToContain('Setup builds .env from env.base, which is missing or unreadable')
            ->assertFailed();

        Process::assertNothingRan();

        $this->assertFileDoesNotExist($this->environmentDirectory.'/.env');
    }

    public function test_refuses_to_run_without_interaction(): void
    {
        $this->artisan('setup', ['--no-interaction' => true])
            ->expectsOutputToContain('cannot run with --no-interaction')
            ->assertFailed();

        $this->assertFileDoesNotExist($this->environmentDirectory.'/.env');
    }

    private function runWithGitLabAndNoMailer(): PendingCommand
    {
        return $this->artisan('setup')
            ->expectsQuestion('Which web server will run MataSecret?', 'traditional')
            ->expectsQuestion('Domain', 'secrets.example.com')
            ->expectsQuestion('HTTPS port', '443')
            ->expectsQuestion('Where should secrets be stored?', 'apcu')
            ->expectsQuestion('Which provider will people sign in with?', 'gitlab')
            ->expectsQuestion('GitLab client ID', 'gitlab-client-id')
            ->expectsQuestion('GitLab client secret', 'gitlab-client-secret')
            ->expectsQuestion('GitLab URL', '')
            ->expectsQuestion('Email domains allowed to sign in and receive secret links', 'example.com')
            ->expectsQuestion('How should MataSecret send email?', 'none');
    }

    /**
     * Replace Composer and the processes setup runs, which would otherwise change this
     * project's dependencies. Every process succeeds unless $processes says otherwise.
     *
     * @param  list<string>  $installed
     * @param  array<string, ProcessResult>  $processes
     */
    private function composer(array $installed = [], array $processes = []): void
    {
        $composer = Mockery::mock(Composer::class);
        $composer->shouldReceive('hasPackage')->andReturnUsing(fn (string $package): bool => in_array($package, $installed, true));
        $composer->shouldReceive('findComposer')->andReturn(['composer']);
        $this->app->instance('composer', $composer);

        Process::fake([...$processes, '*' => Process::result()]);
    }

    /**
     * @param  list<string>  $command
     */
    private function assertRan(array $command): void
    {
        Process::assertRan(fn (PendingProcess $process): bool => $process->command === $command && $process->path === base_path());
    }

    private function assertComposerDidntRun(string $command): void
    {
        Process::assertDidntRun(fn (PendingProcess $process): bool => is_array($process->command) && array_slice($process->command, 0, 2) === ['composer', $command]);
    }

    private function redisAnswers(bool $responds = true): void
    {
        $connection = Mockery::mock(Connection::class);
        $ping = $connection->shouldReceive('command')->with('ping');
        $responds ? $ping->andReturn(true) : $ping->andThrow(new RedisException('Connection refused'));

        Redis::shouldReceive('connection')->with('setup')->andReturn($connection);
        Redis::shouldReceive('purge')->with('setup');
    }

    /**
     * @return array<string, string>
     */
    private function writtenEnvironment(): array
    {
        /** @var array<string, string> */
        return Dotenv::parse(File::get($this->environmentDirectory.'/.env'));
    }
}
