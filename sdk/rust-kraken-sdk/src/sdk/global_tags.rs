use kraken::api::handler::global_tags::schema::ListGlobalTags;

use crate::sdk::utils::KrakenRequest;
use crate::{KrakenClient, KrakenResult};

impl KrakenClient {
    /// Get all global tags
    pub async fn get_all_global_tags(&self) -> KrakenResult<ListGlobalTags> {
        #[allow(clippy::expect_used)]
        let url = self.base_url.join("api/v1/globalTags").expect("Valid url");

        self.make_request(KrakenRequest::get(url).build()).await
    }
}
