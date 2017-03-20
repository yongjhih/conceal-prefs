# Conceal SharedPreferences

Wrap facebook/conceal as SharedPreferences for Android.

Actually, facebook/conceal used to apply on large file not small data. It's a project just for fun.

## Usage

```java
SharedPreferences prefs = new ConcealPreferences(context);
```

## Installation

```gradle
repositories {
    jcenter()

}

dependencies {
    compile 'com.github.yongjhih:conceal-prefs:0.0.1'
}
```

## LICENSE

Apache 2.0
