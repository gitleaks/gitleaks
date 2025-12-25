# Инструкции по сборке библиотеки

## Быстрая проверка зависимостей

Перед сборкой проверьте, что все зависимости установлены:

```bash
bash build-scripts/check-dependencies.sh
```

Скрипт проверит наличие Go, CGO и C компилятора, и предоставит инструкции по установке недостающих компонентов.

## Требования

Для сборки Go библиотеки требуется:

1. **Go 1.24+** с поддержкой CGO
2. **C компилятор**:
   - **Windows**: MinGW-w64 (gcc) или MSVC
   - **Linux**: gcc (обычно установлен по умолчанию)
   - **macOS**: clang (обычно установлен через Xcode Command Line Tools)

## Установка зависимостей

### Windows

#### Вариант 1: MSYS2 (рекомендуется)

1. Скачайте и установите MSYS2 с https://www.msys2.org/
2. Откройте MSYS2 UCRT64 terminal (или MINGW64)
3. Установите MinGW-w64:
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-gcc  # для UCRT64
   # или
   pacman -S mingw-w64-x86_64-gcc       # для MINGW64
   ```
4. Добавьте путь к компилятору в PATH:
   - Для UCRT64: `C:\msys64\ucrt64\bin`
   - Для MINGW64: `C:\msys64\mingw64\bin`
5. Проверьте установку:
   ```bash
   gcc --version
   ```

#### Вариант 2: TDM-GCC

1. Скачайте TDM-GCC с https://jmeubank.github.io/tdm-gcc/
2. Установите, выбрав опцию добавления в PATH
3. Проверьте установку:
   ```bash
   gcc --version
   ```

#### Вариант 3: MinGW-w64 (standalone)

1. Скачайте с https://www.mingw-w64.org/downloads/
2. Распакуйте и добавьте `bin` директорию в PATH
3. Проверьте установку:
   ```bash
   gcc --version
   ```

#### Вариант 4: Visual Studio Build Tools (MSVC)

1. Установите Visual Studio Build Tools или Visual Studio Community
2. Откройте "Developer Command Prompt for VS" или используйте `vcvarsall.bat`
3. Проверьте установку:
   ```bash
   cl
   ```

**Важно:** При использовании MSVC может потребоваться дополнительная настройка переменных окружения. MinGW-w64 (gcc) рекомендуется как более простой вариант.

### Linux

Обычно gcc уже установлен. Если нет:
```bash
sudo apt-get install gcc  # Ubuntu/Debian
sudo yum install gcc      # CentOS/RHEL
```

### macOS

Установите Xcode Command Line Tools:
```bash
xcode-select --install
```

## Сборка библиотеки

### Шаг 1: Проверка зависимостей

```bash
bash build-scripts/check-dependencies.sh
```

Убедитесь, что все зависимости установлены перед продолжением.

### Шаг 2: Сборка для текущей платформы

**Windows:**
```bash
# В Git Bash, MSYS2 или WSL
bash build-scripts/build-windows.sh
```

**Linux:**
```bash
bash build-scripts/build-linux.sh
```

**macOS:**
```bash
bash build-scripts/build-darwin.sh amd64   # для Intel
bash build-scripts/build-darwin.sh arm64   # для Apple Silicon
```

**Примечание для Windows:** Если вы используете MSYS2, убедитесь, что запускаете скрипт в правильном терминале (UCRT64 или MINGW64), где доступен `gcc`.

### Сборка для всех платформ

```bash
bash build-scripts/build-all.sh
```

Библиотеки будут созданы в:
- `build/out/windows-amd64/libgitleaks.dll`
- `build/out/linux-amd64/libgitleaks.so`
- `build/out/darwin-amd64/libgitleaks.dylib`
- `build/out/darwin-arm64/libgitleaks.dylib`

## Кроссплатформенная сборка JVM библиотеки

JVM библиотека автоматически упаковывает нативные библиотеки для всех платформ в JAR файл. Это позволяет использовать библиотеку на любой ОС независимо от платформы, на которой она была собрана.

### Автоматическая упаковка нативных библиотек

При сборке JAR файла (`./gradlew jvmJar`), нативные библиотеки автоматически копируются в структуру ресурсов:
- `META-INF/native/win32-x86-64/libgitleaks.dll`
- `META-INF/native/linux-x86-64/libgitleaks.so`
- `META-INF/native/darwin-x86-64/libgitleaks.dylib`
- `META-INF/native/darwin-aarch64/libgitleaks.dylib`

JNA автоматически найдет и загрузит правильную библиотеку для текущей платформы из classpath.

### Проверка наличия библиотек

По умолчанию при сборке JAR проверяется наличие всех необходимых нативных библиотек. Если некоторые библиотеки отсутствуют, будет выведено предупреждение, но сборка продолжится с доступными библиотеками.

**Для полной кроссплатформенной сборки** соберите все нативные библиотеки:
```bash
bash build-scripts/build-all.sh
```

**Для локальной тестовой сборки** можно пропустить проверку:
```bash
cd kotlin
./gradlew jvmJar -PskipNativeLibraryCheck=true
```

Это позволит собрать JAR только с библиотеками для текущей платформы, что полезно для локальной разработки и тестирования.

### Сборка JVM библиотеки

```bash
cd kotlin
./gradlew jvmJar
```

Собранный JAR будет содержать все необходимые нативные библиотеки и может быть использован на любой поддерживаемой платформе.

## Запуск тестов

После сборки библиотеки запустите тесты:

```bash
cd kotlin
./gradlew jvmTest
```

Тесты автоматически найдут библиотеку в `build/out/` в зависимости от платформы.

## Проверка сборки

Убедитесь, что файл библиотеки создан:

**Windows:**
```bash
dir build\out\windows-amd64\libgitleaks.dll
```

**Linux:**
```bash
ls -lh build/out/linux-amd64/libgitleaks.so
```

**macOS:**
```bash
ls -lh build/out/darwin-*/libgitleaks.dylib
```



