#!/usr/bin/env python3
"""
LLM Attack Consumer
Consumes attack logs from Kafka, enriches with LLM analysis, and stores in Elasticsearch
"""

import os
import json
import time
from datetime import datetime
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch, helpers
from llm_analyzer import LLMAttackAnalyzer


class LLMAttackConsumer:
    """
    Kafka consumer that processes attack logs with LLM analysis
    """

    def __init__(self):
        # Kafka configuration
        self.kafka_servers = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
        self.kafka_topics = os.getenv('KAFKA_TOPICS', 'honeypot-attacks').split(',')
        self.kafka_group = os.getenv('KAFKA_GROUP', 'llm-analyzer-group')

        # Elasticsearch configuration
        self.es_host = os.getenv('ES_HOST', 'http://localhost:9200')
        self.es_index_prefix = 'llm-analysis'

        # Ollama configuration
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'llama3.2')

        # Initialize components
        self.consumer = None
        self.es_client = None
        self.llm_analyzer = None

        # Statistics
        self.stats = {
            'messages_processed': 0,
            'llm_analyses': 0,
            'es_indexed': 0,
            'errors': 0,
            'start_time': datetime.now()
        }

        print("🚀 LLM Attack Consumer initializing...")
        print(f"   Kafka: {self.kafka_servers}")
        print(f"   Topics: {self.kafka_topics}")
        print(f"   Elasticsearch: {self.es_host}")
        print(f"   Ollama: {self.ollama_url} ({self.ollama_model})")

    def initialize(self):
        """Initialize Kafka consumer, Elasticsearch, and LLM analyzer"""

        # Initialize Kafka consumer
        print("\n📡 Connecting to Kafka...")
        try:
            self.consumer = KafkaConsumer(
                *self.kafka_topics,
                bootstrap_servers=self.kafka_servers,
                group_id=self.kafka_group,
                auto_offset_reset='latest',  # Start from latest (not earliest)
                enable_auto_commit=True,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                consumer_timeout_ms=1000  # 1 second timeout for poll
            )
            print(f"✅ Kafka consumer connected to {self.kafka_servers}")
        except Exception as e:
            print(f"❌ Failed to connect to Kafka: {e}")
            raise

        # Initialize Elasticsearch
        print("\n🔍 Connecting to Elasticsearch...")
        try:
            self.es_client = Elasticsearch([self.es_host])
            if self.es_client.ping():
                print(f"✅ Elasticsearch connected to {self.es_host}")
            else:
                raise Exception("Elasticsearch ping failed")
        except Exception as e:
            print(f"❌ Failed to connect to Elasticsearch: {e}")
            raise

        # Initialize LLM analyzer
        print("\n🤖 Initializing LLM analyzer...")
        try:
            self.llm_analyzer = LLMAttackAnalyzer(
                ollama_url=self.ollama_url,
                model=self.ollama_model
            )

            # Wait for Ollama to be ready
            print("⏳ Waiting for Ollama to be ready...")
            max_retries = 30
            for i in range(max_retries):
                if self.llm_analyzer.test_connection():
                    print("✅ Ollama is ready")
                    break
                print(f"   Retry {i+1}/{max_retries}...")
                time.sleep(10)
            else:
                print("⚠️  Ollama not ready, will use rule-based fallback")

        except Exception as e:
            print(f"❌ Failed to initialize LLM analyzer: {e}")
            raise

        print("\n✅ All components initialized successfully!")

    def process_message(self, message):
        """
        Process a single Kafka message

        Args:
            message: Kafka message containing attack log
        """
        try:
            self.stats['messages_processed'] += 1

            # Extract log data
            log_data = message.value

            # Check if this is an attack log with LLM context
            if log_data.get('log_category') != 'attack':
                print(f"⏭️  Skipping non-attack log (category: {log_data.get('log_category')})")
                return

            if not log_data.get('llm_context'):
                print(f"⏭️  Skipping attack log without LLM context")
                return

            # Extract necessary data
            ip = log_data.get('ip', 'unknown')
            attack_tool = log_data.get('attack_tool', 'unknown')
            llm_context = log_data.get('llm_context', {})

            print(f"\n{'='*70}")
            print(f"🚨 Processing Attack from {ip}")
            print(f"   Tool: {attack_tool}")
            print(f"   Timestamp: {log_data.get('timestamp')}")
            print(f"{'='*70}")

            # Analyze with LLM
            print(f"🤖 Running LLM analysis...")
            analysis = self.llm_analyzer.analyze_attack_intent(llm_context)
            self.stats['llm_analyses'] += 1

            print(f"\n📊 LLM Analysis Results:")
            print(f"   Intent: {analysis.get('intent', 'Unknown')[:80]}...")
            print(f"   Stage: {analysis.get('attack_stage', 'Unknown')}")
            print(f"   Sophistication: {analysis.get('sophistication', 'Unknown')}")
            print(f"   Threat: {analysis.get('threat_assessment', '')[:80]}...")

            # Generate defense playbook
            print(f"\n📖 Generating defense playbook...")
            playbook = self.llm_analyzer.generate_defense_playbook(llm_context, analysis)

            # Combine everything for storage
            enriched_log = {
                # Original log data
                **log_data,

                # LLM analysis
                'llm_analysis': analysis,

                # Defense playbook
                'defense_playbook': playbook,

                # Metadata
                'processed_at': datetime.now().isoformat(),
                'llm_model': self.ollama_model,
                'consumer_version': '2.0.0'
            }

            # Store in Elasticsearch
            self._store_in_elasticsearch(enriched_log)

            # Print summary
            print(f"\n✅ Attack processed successfully!")
            print(f"   - LLM Analysis: ✓")
            print(f"   - Defense Playbook: ✓")
            print(f"   - Elasticsearch: ✓")
            print(f"\n💡 Top Recommendation: {playbook['immediate_actions'][0] if playbook['immediate_actions'] else 'N/A'}")

        except Exception as e:
            self.stats['errors'] += 1
            print(f"❌ Error processing message: {e}")
            import traceback
            traceback.print_exc()

    def _store_in_elasticsearch(self, enriched_log):
        """Store enriched log in Elasticsearch"""
        try:
            # Create index name (e.g., llm-analysis-2025-11-19)
            date_str = datetime.now().strftime('%Y-%m-%d')
            index_name = f"{self.es_index_prefix}-{date_str}"

            # Index document
            result = self.es_client.index(
                index=index_name,
                document=enriched_log
            )

            self.stats['es_indexed'] += 1
            print(f"📊 Stored in Elasticsearch: {index_name} (ID: {result['_id']})")

        except Exception as e:
            print(f"❌ Failed to store in Elasticsearch: {e}")
            raise

    def run(self):
        """Main consumer loop"""
        print(f"\n{'='*70}")
        print(f"🎯 LLM Attack Consumer is running...")
        print(f"   Waiting for attack logs from Kafka topics: {self.kafka_topics}")
        print(f"   Press Ctrl+C to stop")
        print(f"{'='*70}\n")

        try:
            for message in self.consumer:
                self.process_message(message)

                # Print stats every 10 messages
                if self.stats['messages_processed'] % 10 == 0:
                    self._print_stats()

        except KeyboardInterrupt:
            print("\n\n⚠️  Received interrupt signal, shutting down...")
        except Exception as e:
            print(f"\n\n❌ Fatal error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.shutdown()

    def _print_stats(self):
        """Print consumer statistics"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        rate = self.stats['messages_processed'] / runtime if runtime > 0 else 0

        print(f"\n📊 Consumer Statistics:")
        print(f"   Messages processed: {self.stats['messages_processed']}")
        print(f"   LLM analyses: {self.stats['llm_analyses']}")
        print(f"   ES indexed: {self.stats['es_indexed']}")
        print(f"   Errors: {self.stats['errors']}")
        print(f"   Runtime: {int(runtime)}s")
        print(f"   Rate: {rate:.2f} msg/sec\n")

    def shutdown(self):
        """Cleanup and shutdown"""
        print(f"\n{'='*70}")
        print(f"🛑 Shutting down LLM Attack Consumer...")
        print(f"{'='*70}")

        # Print final stats
        self._print_stats()

        # Close connections
        if self.consumer:
            self.consumer.close()
            print("✅ Kafka consumer closed")

        if self.es_client:
            self.es_client.close()
            print("✅ Elasticsearch client closed")

        print(f"\n✅ LLM Attack Consumer stopped successfully")


def main():
    """Main entry point"""
    consumer = LLMAttackConsumer()

    try:
        # Initialize
        consumer.initialize()

        # Run
        consumer.run()

    except Exception as e:
        print(f"❌ Failed to start consumer: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
