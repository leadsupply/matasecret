<?php

namespace App\Console\Commands;

use App\Enums\AuthProvider;
use App\Enums\MailProvider;
use App\Enums\SecretStoreDriver;
use App\Enums\WebServer;
use App\Setup\EnvironmentFile;
use App\Setup\SetupAnswers;
use App\Setup\SetupField;
use Illuminate\Console\Command;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Composer;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Redis;
use RuntimeException;
use Throwable;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\password;
use function Laravel\Prompts\select;
use function Laravel\Prompts\text;

class SetupCommand extends Command
{
    protected $signature = 'setup';

    protected $description = 'Setup the environment and dependencies';

    public function handle(): int
    {
        if (! $this->input->isInteractive()) {
            $this->components->error('It cannot run with --no-interaction.');

            return self::FAILURE;
        }

        $this->output->title('MataSecret setup');

        $environmentPath = $this->laravel->environmentFilePath();
        $templatePath = $this->laravel->environmentPath().'/env.base';

        try {
            $environmentFile = EnvironmentFile::fromFile($templatePath);
        } catch (RuntimeException) {
            $this->components->error("Setup builds .env from env.base, which is missing or unreadable: {$templatePath}");

            return self::FAILURE;
        }

        $answers = $this->askQuestions();

        $this->showSummary($answers, File::exists($environmentPath));

        if (! confirm('Apply this configuration?', default: false)) {
            $this->components->warn('Setup cancelled. Nothing was changed.');

            return self::FAILURE;
        }

        $this->fillEnvironmentFile($environmentFile, $answers);

        if (! $this->installPackages($answers)) {
            $this->components->error('Composer failed. composer.json and composer.lock were restored and .env was not changed. If vendor/ is out of sync, run composer install.');

            return self::FAILURE;
        }

        $this->replaceEnvironmentFile($environmentFile, $environmentPath);
        $this->callSilently('config:clear');

        if (! $this->installProductionDependencies()) {
            $this->components->error('composer install --no-dev failed. .env is already written: fix the error above, then run composer install --no-dev and build the frontend.');

            return self::FAILURE;
        }

        $packageManager = $this->nodePackageManager();

        if (! $this->buildFrontend($packageManager)) {
            $this->components->error("The frontend build failed. .env is already written: fix the error above, then run {$packageManager} install && {$packageManager} run build.");

            return self::FAILURE;
        }

        $this->components->info('MataSecret is configured. Next steps:');

        foreach ($answers->nextSteps(public_path()) as $step) {
            $this->line('  • '.$step);
        }

        return self::SUCCESS;
    }

    private function askQuestions(): SetupAnswers
    {
        $webServer = WebServer::from($this->askField(new SetupField('server', 'Which web server will run MataSecret?', options: WebServer::options(), default: WebServer::FrankenPhp->value)));

        $behindProxy = $webServer === WebServer::FrankenPhp && ! confirm(
            'Should FrankenPHP obtain its own TLS certificate?',
            hint: 'Answer no when a reverse proxy in front of FrankenPHP has the certificate.',
        );

        $domain = $this->askField(new SetupField('domain', $behindProxy ? 'Public domain' : 'Domain', format: 'host', hint: 'The host name people open, such as secrets.example.com.'));
        $listenAddress = $trustedProxies = '';

        if ($behindProxy) {
            $port = $this->askField(new SetupField('port', 'Port FrankenPHP listens on', format: 'port', default: '8000'));
            $listenAddress = $this->askField(new SetupField('listen', 'Address FrankenPHP listens on', format: 'ip', default: '127.0.0.1', hint: 'Use 0.0.0.0 when the proxy runs on another host or container.'));
            $trustedProxies = $this->askField(new SetupField('proxies', 'Trusted proxy addresses', format: 'proxies', default: '127.0.0.1', hint: 'IP addresses or CIDR ranges, separated by commas.'));
        } else {
            $port = $this->askField(new SetupField('port', 'HTTPS port', format: 'port', default: '443'));
        }

        $secretStore = SecretStoreDriver::from($this->askField(new SetupField('store', 'Where should secrets be stored?', options: SecretStoreDriver::options(), default: SecretStoreDriver::Apcu->value)));
        $redis = $secretStore === SecretStoreDriver::Redis ? $this->askRedis() : null;

        $authProvider = AuthProvider::from($this->askField(new SetupField('provider', 'Which provider will people sign in with?', options: AuthProvider::options(), default: AuthProvider::GoogleWorkspace->value)));
        $clientId = $this->askField(new SetupField('AUTH_CLIENT_ID', $authProvider->clientIdLabel()));
        $clientSecret = $authProvider->needsClientSecret()
            ? $this->askField(new SetupField('AUTH_CLIENT_SECRET', $authProvider->clientSecretLabel(), secret: true))
            : '';

        $authSettings = [];

        foreach ($authProvider->extraFields() as $field) {
            $authSettings[$field->key] = $this->askField($field);
        }

        $allowedDomains = $this->askAllowedDomains($domain);

        $mailProvider = MailProvider::from($this->askField(new SetupField('mailer', 'How should MataSecret send email?', options: MailProvider::options(), default: MailProvider::Smtp->value)));
        $mailSettings = [];

        foreach ($mailProvider->fields() as $field) {
            $mailSettings[$field->key] = $this->askField($field);
        }

        $mailFromAddress = $mailFromName = '';

        if ($mailProvider !== MailProvider::None) {
            $mailFromAddress = $this->askField(new SetupField('MAIL_FROM_ADDRESS', 'From address', format: 'email', default: 'no-reply@'.$domain));
            $mailFromName = $this->askField(new SetupField('MAIL_FROM_NAME', 'From name', default: 'MataSecret'));
        }

        return new SetupAnswers(
            webServer: $webServer,
            domain: $domain,
            port: (int) $port,
            behindProxy: $behindProxy,
            listenAddress: $listenAddress,
            trustedProxies: $trustedProxies,
            secretStore: $secretStore,
            redis: $redis,
            authProvider: $authProvider,
            clientId: $clientId,
            clientSecret: $clientSecret,
            authSettings: $authSettings,
            allowedDomains: $allowedDomains,
            mailProvider: $mailProvider,
            mailSettings: $mailSettings,
            mailFromAddress: $mailFromAddress,
            mailFromName: $mailFromName,
        );
    }

    private function askField(SetupField $field): string
    {
        if ($field->options !== []) {
            return (string) select(
                label: $field->label,
                options: $field->options,
                default: $field->default === '' ? null : $field->default,
                scroll: 10,
                hint: $field->hint,
            );
        }

        $validate = fn (string $value): ?string => $field->validate(trim($value));

        $answer = $field->secret
            ? password(label: $field->label, validate: $validate, hint: $field->hint)
            : text(label: $field->label, default: $field->default, validate: $validate, hint: $field->hint);

        return $field->normalize($answer);
    }

    /**
     * Ask for the Redis connection until it answers, or the user moves on without it.
     *
     * @return array{host: string, port: string, username: string, password: string, database: string}
     */
    private function askRedis(): array
    {
        do {
            $redis = [
                'host' => $this->askField(new SetupField('REDIS_HOST', 'Redis host', format: 'host', default: '127.0.0.1')),
                'port' => $this->askField(new SetupField('REDIS_PORT', 'Redis port', format: 'port', default: '6379')),
                'username' => $this->askField(new SetupField('REDIS_USERNAME', 'Redis username', required: false, hint: 'Leave empty unless Redis uses ACL users.')),
                'password' => $this->askField(new SetupField('REDIS_PASSWORD', 'Redis password', required: false, secret: true)),
                'database' => $this->askField(new SetupField('REDIS_SECRETS_DB', 'Redis database for secrets', format: 'integer', default: '2')),
            ];

            if ($this->redisResponds($redis)) {
                $this->components->info('Redis answered.');

                return $redis;
            }
        } while (confirm('Redis did not answer. Enter the connection details again?'));

        return $redis;
    }

    /**
     * @param  array{host: string, port: string, username: string, password: string, database: string}  $redis
     */
    private function redisResponds(array $redis): bool
    {
        config(['database.redis.setup' => [
            'host' => $redis['host'],
            'port' => $redis['port'],
            'username' => $redis['username'] === '' ? null : $redis['username'],
            'password' => $redis['password'] === '' ? null : $redis['password'],
            'database' => $redis['database'],
            'timeout' => 3,
        ]]);

        try {
            Redis::connection('setup')->command('ping');

            return true;
        } catch (Throwable) {
            return false;
        } finally {
            Redis::purge('setup');
        }
    }

    /**
     * @return list<string>
     */
    private function askAllowedDomains(string $domain): array
    {
        $labels = explode('.', $domain);
        $suggestion = count($labels) > 2 ? implode('.', array_slice($labels, 1)) : $domain;

        $answer = text(
            label: 'Email domains allowed to sign in and receive secret links',
            default: $suggestion,
            validate: function (string $value): ?string {
                $domains = self::splitDomains($value);

                if ($domains === []) {
                    return 'Enter at least one domain.';
                }

                foreach ($domains as $candidate) {
                    if (! SetupField::isHostname($candidate)) {
                        return "{$candidate} is not a valid domain.";
                    }
                }

                return null;
            },
            hint: 'Separate several domains with commas, such as example.com,example.org.',
        );

        return self::splitDomains($answer);
    }

    /**
     * @return list<string>
     */
    private static function splitDomains(string $value): array
    {
        return array_values(array_unique(array_filter(array_map(
            fn (string $domain): string => strtolower(trim($domain)),
            explode(',', $value),
        ))));
    }

    private function showSummary(SetupAnswers $answers, bool $replacesEnvironmentFile): void
    {
        foreach ($answers->summary() as $section => $rows) {
            $this->table([$section, ''], $rows);
        }

        $warnings = $answers->warnings();

        foreach ($answers->requiredExtensions() as $extension) {
            if (! extension_loaded($extension)) {
                $warnings[] = "The {$extension} extension is not loaded in this PHP CLI. Make sure the web server's PHP loads it.";
            }
        }

        if ($replacesEnvironmentFile) {
            $warnings[] = 'The current .env will be backed up and replaced. The new APP_KEY signs everyone out and makes stored secrets unreadable.';
        }

        $warnings[] = 'Development dependencies will be removed (composer install --no-dev) and the frontend will be built for production.';

        foreach ($warnings as $warning) {
            $this->components->warn($warning);
        }
    }

    /**
     * Add the packages the answers need and remove the ones setup added before but no
     * longer needs. On failure composer.json and composer.lock are put back.
     *
     * The composer.json scripts are skipped: post-update-cmd calls boost:update, which does
     * not exist under the production .env. The production install that follows rebuilds
     * the autoloader and the package manifest.
     */
    private function installPackages(SetupAnswers $answers): bool
    {
        /** @var Composer $composer */
        $composer = $this->laravel->make('composer');
        $wanted = $answers->packages();

        $stale = array_values(array_filter(
            SetupAnswers::managedPackages(),
            fn (string $package): bool => ! in_array($package, $wanted, true) && $composer->hasPackage($package),
        ));
        $missing = array_values(array_filter($wanted, fn (string $package): bool => ! $composer->hasPackage($package)));

        if ($stale === [] && $missing === []) {
            return true;
        }

        $snapshot = [];

        foreach ([base_path('composer.json'), base_path('composer.lock')] as $path) {
            $snapshot[$path] = File::exists($path) ? File::get($path) : null;
        }

        $installed = ($stale === [] || $this->runComposer(['remove', ...$stale, '--no-scripts']))
            && ($missing === [] || $this->runComposer(['require', ...$missing, '--no-scripts']));

        if (! $installed) {
            foreach ($snapshot as $path => $contents) {
                if ($contents !== null && File::get($path) !== $contents) {
                    File::put($path, $contents);
                }
            }
        }

        return $installed;
    }

    /**
     * Install what composer.lock lists for production, leaving out the development tools.
     */
    private function installProductionDependencies(): bool
    {
        return $this->runComposer(['install', '--no-dev', '--optimize-autoloader']);
    }

    /**
     * @param  list<string>  $arguments
     */
    private function runComposer(array $arguments): bool
    {
        /** @var Composer $composer */
        $composer = $this->laravel->make('composer');

        return Process::path(base_path())
            ->forever()
            ->env(['COMPOSER_MEMORY_LIMIT' => '-1'])
            ->run([...$composer->findComposer(), ...$arguments, '--no-interaction'], $this->writeProcessOutput(...))
            ->successful();
    }

    /**
     * pnpm when it is installed, npm otherwise.
     */
    private function nodePackageManager(): string
    {
        return Process::run('command -v pnpm')->successful() ? 'pnpm' : 'npm';
    }

    private function buildFrontend(string $packageManager): bool
    {
        foreach ([[$packageManager, 'install'], [$packageManager, 'run', 'build']] as $command) {
            $result = Process::path(base_path())->forever()->run($command, $this->writeProcessOutput(...));

            if ($result->failed()) {
                return false;
            }
        }

        return true;
    }

    private function writeProcessOutput(string $type, string $line): void
    {
        $this->output->write($line);
    }

    /**
     * Put the answers and a new APP_KEY into the template, before anything is changed.
     */
    private function fillEnvironmentFile(EnvironmentFile $file, SetupAnswers $answers): void
    {
        foreach ($answers->obsoleteVariables() as $prefix) {
            $file->forget($prefix);
        }

        $environment = [
            'APP_KEY' => 'base64:'.base64_encode(Encrypter::generateKey((string) config('app.cipher'))),
            ...$answers->environment(),
        ];

        foreach ($environment as $key => $value) {
            $file->set($key, $value);
        }
    }

    private function replaceEnvironmentFile(EnvironmentFile $file, string $environmentPath): void
    {
        $mode = 0640;

        if (File::exists($environmentPath)) {
            $mode = fileperms($environmentPath) & 0777;
            $backupPath = $environmentPath.'.backup-'.now()->format('YmdHis');

            File::copy($environmentPath, $backupPath);
            File::chmod($backupPath, $mode);

            $this->components->info('The previous .env was saved as '.basename($backupPath).'.');
        }

        $file->writeTo($environmentPath, $mode);
    }
}
