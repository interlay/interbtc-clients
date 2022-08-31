use crate::currency::*;

pub trait KnownPairs {
    fn has_pair(&self, currency_pair: &CurrencyPair) -> bool;

    fn has_reciprocal(&self, currency_pair: &CurrencyPair) -> bool {
        let inverted = (*currency_pair).invert();
        self.has_pair(&inverted)
    }

    fn calculate_shortest_route(&self, currency_pair: CurrencyPair) -> Vec<CurrencyPair>;

    fn get_best_route(&self, currency_pair: CurrencyPair) -> Vec<CurrencyPair> {
        if self.has_pair(&currency_pair) {
            vec![currency_pair]
        } else if self.has_reciprocal(&currency_pair) {
            vec![currency_pair.invert()]
        } else {
            self.calculate_shortest_route(currency_pair)
        }
    }
}

impl KnownPairs for Vec<CurrencyPair> {
    fn has_pair(&self, currency_pair: &CurrencyPair) -> bool {
        self.iter().any(|cup| cup == currency_pair)
    }

    fn calculate_shortest_route(&self, currency_pair: CurrencyPair) -> Vec<CurrencyPair> {
        fn without_currency_pair(pairs: Vec<CurrencyPair>, currency_pair: CurrencyPair) -> Vec<CurrencyPair> {
            let mut pairs = pairs;
            pairs.retain(|&x| x != currency_pair);
            pairs
        }

        fn pairs_with_next(currency: Currency, pairs: Vec<CurrencyPair>) -> Vec<(CurrencyPair, Currency)> {
            pairs
                .into_iter()
                .filter_map(|cup| {
                    if cup.base == currency {
                        Some((cup, cup.quote))
                    } else if cup.quote == currency {
                        Some((cup, cup.base))
                    } else {
                        None
                    }
                })
                .collect()
        }

        fn find_route(
            next: Currency,
            quote: Currency,
            pairs: Vec<CurrencyPair>,
            parents: Vec<CurrencyPair>,
            routes: &mut Vec<Vec<CurrencyPair>>,
        ) {
            for (pair, next) in pairs_with_next(next, pairs.clone()) {
                let mut current = parents.to_vec();
                current.push(pair);

                if pair.contains(quote) {
                    // found target
                    routes.push(current);
                } else {
                    // keep looking
                    find_route(next, quote, without_currency_pair(pairs.clone(), pair), current, routes);
                }
            }
        }

        let start = currency_pair.base;
        let end = currency_pair.quote;
        let mut routes = vec![];
        find_route(start, end, self.clone(), vec![], &mut routes);

        let shortest_route = routes.into_iter().min_by(|x, y| x.len().cmp(&y.len()));
        if let Some(route) = shortest_route {
            route
        } else {
            vec![]
        }
    }
}
