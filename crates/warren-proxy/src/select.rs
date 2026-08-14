//! Exit candidate ordering from the user's constraint list.

use crate::config::ExitFilter;

/// Orders `exits` by the user's priority filters.
///
/// With no filters the input order is preserved (the verified directory's
/// order). With filters, only matching exits survive, grouped by the index of
/// the first filter they match (so `WARREN_EXITS=fi,se` tries every Finnish
/// exit before any Swedish one), stable within a group.
pub fn order_exits<T>(
    exits: Vec<T>,
    filters: &[ExitFilter],
    country: impl Fn(&T) -> String,
    city: impl Fn(&T) -> String,
) -> Vec<T> {
    if filters.is_empty() {
        return exits;
    }
    let mut keyed: Vec<(usize, T)> = exits
        .into_iter()
        .filter_map(|exit| {
            let cc = country(&exit).to_ascii_lowercase();
            let ct = city(&exit).to_ascii_lowercase();
            filters
                .iter()
                .position(|f| f.country == cc && f.city.as_deref().is_none_or(|c| c == ct))
                .map(|rank| (rank, exit))
        })
        .collect();
    keyed.sort_by_key(|(rank, _)| *rank);
    keyed.into_iter().map(|(_, exit)| exit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(raw: &[(&str, Option<&str>)]) -> Vec<ExitFilter> {
        raw.iter()
            .map(|(country, city)| ExitFilter {
                country: (*country).to_owned(),
                city: city.map(str::to_owned),
            })
            .collect()
    }

    /// (country, city, tag) test exits.
    fn sample() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("FI", "Helsinki", "fi-1"),
            ("SE", "Stockholm", "se-1"),
            ("FI", "Helsinki", "fi-2"),
            ("DE", "Berlin", "de-1"),
        ]
    }

    fn run(
        exits: Vec<(&'static str, &'static str, &'static str)>,
        f: &[ExitFilter],
    ) -> Vec<&'static str> {
        order_exits(exits, f, |e| e.0.to_owned(), |e| e.1.to_owned())
            .into_iter()
            .map(|e| e.2)
            .collect()
    }

    #[test]
    fn no_filters_keeps_directory_order() {
        assert_eq!(run(sample(), &[]), vec!["fi-1", "se-1", "fi-2", "de-1"]);
    }

    #[test]
    fn country_filter_keeps_only_matches() {
        assert_eq!(
            run(sample(), &filters(&[("fi", None)])),
            vec!["fi-1", "fi-2"]
        );
    }

    #[test]
    fn priority_order_groups_by_first_matching_filter() {
        assert_eq!(
            run(sample(), &filters(&[("se", None), ("fi", None)])),
            vec!["se-1", "fi-1", "fi-2"],
            "every SE exit must rank before any FI exit"
        );
    }

    #[test]
    fn city_filter_narrows_case_insensitively() {
        assert_eq!(
            run(sample(), &filters(&[("fi", Some("helsinki"))])),
            vec!["fi-1", "fi-2"]
        );
        assert_eq!(
            run(sample(), &filters(&[("fi", Some("tampere"))])),
            Vec::<&str>::new()
        );
    }
}
