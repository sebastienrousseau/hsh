// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::loggers::{Log, LogLevel, LogFormat};

    #[test]
    fn test_log_default_values() {
        let log = Log::default();
        assert_eq!(log.session_id, String::default());
        assert_eq!(log.time, String::default());
        assert_eq!(log.level, LogLevel::INFO);
        assert_eq!(log.component, String::default());
        assert_eq!(log.description, String::default());
        assert_eq!(log.format, LogFormat::CLF);
    }

    #[test]
    fn test_log_custom_values() {
        let session_id = "session_id_123";
        let time = "2021-12-01T12:34:56Z";
        let level = LogLevel::ERROR;
        let component = "test_component";
        let description = "test_description";
        let format = LogFormat::JSON;

        let log = Log::new(session_id, time, level.clone(), component, description, format.clone());

        assert_eq!(log.session_id, session_id);
        assert_eq!(log.time, time);
        assert_eq!(log.level, level);
        assert_eq!(log.component, component);
        assert_eq!(log.description, description);
        assert_eq!(log.format, format);
    }

    #[test]
    fn test_log_level_to_string() {
        assert_eq!(format!("{}", LogLevel::INFO), "INFO");
        assert_eq!(format!("{}", LogLevel::ERROR), "ERROR");
        assert_eq!(format!("{}", LogLevel::DEBUG), "DEBUG");
    }

    #[test]
    fn test_log_format_to_string() {
        assert_eq!(format!("{}", LogFormat::CLF), "CLF\n");
        assert_eq!(format!("{}", LogFormat::JSON), "JSON\n");
        assert_eq!(format!("{}", LogFormat::CEF), "CEF\n");
    }

}
