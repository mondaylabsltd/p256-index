use std::{str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use iggy::prelude::{
    Client, CompressionAlgorithm, Identifier, IggyClient, IggyDuration, IggyExpiry, IggyMessage,
    MaxTopicSize, MessageClient, Partitioning, StreamClient, TopicClient,
};

use crate::types::CreateTask;

pub const STREAM_NAME: &str = "p256-index";
pub const TOPIC_NAME: &str = "create";
pub const RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct CreateQueue {
    client: Arc<IggyClient>,
    provisioner: Arc<IggyClient>,
    provision_lock: Arc<tokio::sync::Mutex<()>>,
    stream: Identifier,
    topic: Identifier,
    enqueue_timeout: Duration,
}

#[derive(Debug)]
pub struct QueueError(&'static str);

impl std::fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for QueueError {}

#[async_trait]
pub trait CreateTaskQueue: Send + Sync {
    async fn enqueue(&self, task: &CreateTask) -> Result<(), QueueError>;
}

impl CreateQueue {
    pub async fn connect(
        producer_url: &str,
        provisioner_url: &str,
        enqueue_timeout: Duration,
    ) -> Result<Self, QueueError> {
        let client = IggyClient::from_connection_string(producer_url)
            .map_err(|_| QueueError("invalid Iggy producer connection configuration"))?;
        tokio::time::timeout(CONNECT_TIMEOUT, client.connect())
            .await
            .map_err(|_| QueueError("Iggy producer connection timed out"))?
            .map_err(|_| QueueError("could not connect to Iggy producer"))?;

        let provisioner = IggyClient::from_connection_string(provisioner_url)
            .map_err(|_| QueueError("invalid Iggy provisioner connection configuration"))?;
        tokio::time::timeout(CONNECT_TIMEOUT, provisioner.connect())
            .await
            .map_err(|_| QueueError("Iggy topology provisioner connection timed out"))?
            .map_err(|_| QueueError("could not connect to Iggy topology provisioner"))?;

        Ok(Self {
            client: Arc::new(client),
            provisioner: Arc::new(provisioner),
            provision_lock: Arc::new(tokio::sync::Mutex::new(())),
            stream: STREAM_NAME
                .try_into()
                .map_err(|_| QueueError("invalid Iggy stream name"))?,
            topic: TOPIC_NAME
                .try_into()
                .map_err(|_| QueueError("invalid Iggy topic name"))?,
            enqueue_timeout,
        })
    }

    /// Returns success only after Iggy confirms the append. An error after calling this is an
    /// ambiguous outcome; callers retain Redis state and retry the same task ID later.
    async fn enqueue_inner(&self, task: &CreateTask) -> Result<(), QueueError> {
        let payload = serde_json::to_string(task)
            .map_err(|_| QueueError("could not serialize Iggy create task"))?;
        match self.append(&payload).await {
            Ok(()) => Ok(()),
            Err(first_error) => {
                let created = self.ensure_topology().await?;
                if !created {
                    return Err(first_error);
                }
                self.append(&payload).await
            }
        }
    }

    pub async fn ensure_topology(&self) -> Result<bool, QueueError> {
        let _guard = self.provision_lock.lock().await;
        let stream_missing = self
            .provisioner
            .get_stream(&self.stream)
            .await
            .map_err(|_| QueueError("could not inspect Iggy stream"))?
            .is_none();
        if stream_missing {
            self.create_stream_if_missing().await?;
        }
        let topic_missing = self
            .provisioner
            .get_topic(&self.stream, &self.topic)
            .await
            .map_err(|_| QueueError("could not inspect Iggy topic"))?
            .is_none();
        if topic_missing {
            self.create_topic_if_missing().await?;
        }
        Ok(stream_missing || topic_missing)
    }

    async fn append(&self, payload: &str) -> Result<(), QueueError> {
        let message = IggyMessage::from_str(payload)
            .map_err(|_| QueueError("Iggy create task is invalid"))?;
        let mut messages = [message];
        match tokio::time::timeout(
            self.enqueue_timeout,
            self.client.send_messages(
                &self.stream,
                &self.topic,
                &Partitioning::balanced(),
                &mut messages,
            ),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(QueueError("Iggy rejected the create task")),
            Err(_) => Err(QueueError("Iggy create enqueue timed out")),
        }
    }

    async fn create_stream_if_missing(&self) -> Result<(), QueueError> {
        if self.provisioner.create_stream(STREAM_NAME).await.is_ok() {
            return Ok(());
        }
        if self
            .provisioner
            .get_stream(&self.stream)
            .await
            .map_err(|_| QueueError("could not inspect Iggy stream"))?
            .is_some()
        {
            return Ok(());
        }
        Err(QueueError("could not create Iggy stream"))
    }

    async fn create_topic_if_missing(&self) -> Result<(), QueueError> {
        let expiry = IggyExpiry::ExpireDuration(IggyDuration::new(RETENTION));
        if self
            .provisioner
            .create_topic(
                &self.stream,
                TOPIC_NAME,
                1,
                CompressionAlgorithm::None,
                None,
                expiry,
                MaxTopicSize::ServerDefault,
            )
            .await
            .is_ok()
        {
            return Ok(());
        }
        if self
            .provisioner
            .get_topic(&self.stream, &self.topic)
            .await
            .map_err(|_| QueueError("could not inspect Iggy topic"))?
            .is_some()
        {
            return Ok(());
        }
        Err(QueueError("could not create Iggy topic"))
    }
}

#[async_trait]
impl CreateTaskQueue for CreateQueue {
    async fn enqueue(&self, task: &CreateTask) -> Result<(), QueueError> {
        self.enqueue_inner(task).await
    }
}

#[cfg(test)]
mod tests {
    use std::{env, time::Duration};

    use super::CreateQueue;

    #[tokio::test]
    #[ignore = "requires P256_INDEX_TEST_IGGY_URL"]
    async fn authenticates_to_the_configured_iggy_endpoint() {
        let url = env::var("P256_INDEX_TEST_IGGY_URL")
            .expect("P256_INDEX_TEST_IGGY_URL is required for this integration test");
        CreateQueue::connect(&url, &url, Duration::from_secs(5))
            .await
            .expect("Iggy producer and provisioner connection");
    }
}
