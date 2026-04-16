# Contributing

[GitHub issues](https://github.com/privkeyio/keep-android/issues) and [pull requests](https://github.com/privkeyio/keep-android/pulls) are welcome.

By contributing to this repository, you agree to license your work under the MIT license. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.

## Translations

Keep ships with four seed locales: Portuguese (Brazil), Spanish, German, and Japanese. Translations are welcome for these locales and for new ones.

### Where translations live

- App strings: `app/src/main/res/values-<lang>[-r<REGION>]/strings.xml`, one per locale
- Store listings: `fastlane/metadata/android/<locale>/` with `title.txt`, `short_description.txt`, `full_description.txt`, and `changelogs/<versionCode>.txt`

Locale directory naming follows [Android's BCP-47 convention](https://developer.android.com/guide/topics/resources/multilingual-support) (e.g. `values-pt-rBR`, `values-es`). Fastlane directories use the [supply convention](https://docs.fastlane.tools/actions/supply/#supply-app-metadata-images-and-apks) (e.g. `pt-BR`, `es-ES`).

### Contributing a translation

Right now translations are contributed as pull requests. A managed translation platform (Crowdin or Weblate) is on the backlog; until it lands, follow this flow:

1. Request the locale by opening an issue titled `[translation] <language>`. This lets us coordinate with other translators and reserve the locale directory.
2. Fork the repo and create the `values-<locale>/strings.xml` file. Copy from `values/strings.xml` and translate every element that is not marked `translatable="false"`.
3. (If your locale is one we ship) add `fastlane/metadata/android/<locale>/` with `title.txt` (<= 30 chars), `short_description.txt` (<= 80 chars), `full_description.txt` (<= 4000 chars), and at least one `changelogs/<versionCode>.txt` entry (<= 500 chars).
4. Run `scripts/check-locale-drift.sh` to confirm your locale has every required key and that all printf format specifiers match the default.
5. Open a PR. CI runs the drift check automatically.

### Strings that must not be translated

These `<string>` elements in `values/strings.xml` are marked `translatable="false"` and must remain in English (they are brand or identity strings surfaced to users):

- `app_name`, `foreground_service_title`, `bunker_service_title`, `biometric_unlock_title`

In addition, the `values/strings_*.xml` sibling files (descriptors, connections, backup, common, etc.) are English-only reference resources and carry `tools:ignore="MissingTranslation"`. Do not create translated copies of these files; they are intentionally English-only until they graduate into `strings.xml`.

### Adding a new locale

1. File an issue so maintainers can track locale coverage.
2. Create `app/src/main/res/values-<locale>/strings.xml` by copying `values/strings.xml` and translating every translatable key.
3. Preserve every `%1$s`, `%2$d`, `<xliff:g>` placeholder exactly as in the default file.
4. For plural resources, provide every CLDR quantity required by your locale (for example, Spanish and Portuguese require `one`, `many`, and `other`; Japanese only requires `other`). See the [CLDR plural rules](https://unicode-org.github.io/cldr-staging/charts/latest/supplemental/language_plural_rules.html).
5. Run `scripts/check-locale-drift.sh` and `./gradlew :app:lintDebug` before opening the PR.

### Drift enforcement

`scripts/check-locale-drift.sh` runs in CI and fails the build if any translatable key from `values/strings.xml` is missing from any shipped locale, or if a format specifier diverges from the default. This keeps locales from silently falling behind when new strings are added.
