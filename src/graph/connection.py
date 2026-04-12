"""
Neo4j Connection Manager
========================

Manages connections to Neo4j database for the security graph.
Supports both local and AuraDB (cloud) instances.
"""

import os
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager
import structlog

logger = structlog.get_logger(__name__)

# Try to import neo4j driver
try:
    from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
    from neo4j.exceptions import ServiceUnavailable, AuthError
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("neo4j_not_installed", message="Install with: pip install neo4j")


class Neo4jConnection:
    """
    Async Neo4j connection manager.
    
    Usage:
        async with Neo4jConnection() as conn:
            result = await conn.query("MATCH (n) RETURN n LIMIT 10")
    """
    
    def __init__(
        self,
        uri: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "neo4j"
    ):
        """
        Initialize Neo4j connection.
        
        Args:
            uri: Neo4j URI (bolt:// or neo4j+s://)
            username: Neo4j username
            password: Neo4j password
            database: Database name (default: neo4j)
        """
        if not NEO4J_AVAILABLE:
            raise ImportError("neo4j package not installed. Run: pip install neo4j")
        
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.username = username or os.getenv("NEO4J_USERNAME", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "")
        self.database = database or os.getenv("NEO4J_DATABASE", "neo4j")
        
        self._driver: Optional[AsyncDriver] = None
        self._connected = False
    
    async def connect(self) -> bool:
        """
        Establish connection to Neo4j.
        
        Returns:
            True if connection successful
        """
        try:
            self._driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=30
            )
            
            # Verify connection
            await self._driver.verify_connectivity()
            self._connected = True
            
            logger.info(
                "neo4j_connected",
                uri=self.uri.split("@")[-1] if "@" in self.uri else self.uri,
                database=self.database
            )
            return True
            
        except AuthError as e:
            logger.error("neo4j_auth_failed", error=str(e))
            raise
        except ServiceUnavailable as e:
            logger.error("neo4j_unavailable", error=str(e), uri=self.uri)
            raise
        except Exception as e:
            logger.error("neo4j_connection_failed", error=str(e))
            raise
    
    async def disconnect(self):
        """Close the Neo4j connection."""
        if self._driver:
            await self._driver.close()
            self._connected = False
            logger.info("neo4j_disconnected")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
    
    @asynccontextmanager
    async def session(self) -> AsyncSession:
        """
        Get a Neo4j session.
        
        Usage:
            async with conn.session() as session:
                result = await session.run("MATCH (n) RETURN n")
        """
        if not self._connected or not self._driver:
            await self.connect()
        
        session = self._driver.session(database=self.database)
        try:
            yield session
        finally:
            await session.close()
    
    async def query(
        self, 
        cypher: str, 
        parameters: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0
    ) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query and return results.
        
        Args:
            cypher: Cypher query string
            parameters: Query parameters
            timeout: Query timeout in seconds
            
        Returns:
            List of result records as dictionaries
        """
        async with self.session() as session:
            result = await session.run(cypher, parameters or {})
            records = await result.data()
            return records
    
    async def execute(
        self, 
        cypher: str, 
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a Cypher query and return summary.
        
        Args:
            cypher: Cypher query string
            parameters: Query parameters
            
        Returns:
            Query execution summary
        """
        async with self.session() as session:
            result = await session.run(cypher, parameters or {})
            summary = await result.consume()
            return {
                "nodes_created": summary.counters.nodes_created,
                "nodes_deleted": summary.counters.nodes_deleted,
                "relationships_created": summary.counters.relationships_created,
                "relationships_deleted": summary.counters.relationships_deleted,
                "properties_set": summary.counters.properties_set,
            }
    
    async def batch_execute(
        self, 
        queries: List[tuple[str, Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Execute multiple queries in a transaction.
        
        Args:
            queries: List of (cypher, parameters) tuples
            
        Returns:
            List of execution summaries
        """
        async with self.session() as session:
            async def run_batch(tx):
                results = []
                for cypher, params in queries:
                    result = await tx.run(cypher, params)
                    summary = await result.consume()
                    results.append({
                        "nodes_created": summary.counters.nodes_created,
                        "relationships_created": summary.counters.relationships_created,
                    })
                return results
            
            return await session.execute_write(run_batch)
    
    async def create_schema(self, schema_queries: List[str]):
        """
        Execute schema creation queries.
        
        Args:
            schema_queries: List of Cypher queries for indexes/constraints
        """
        for query in schema_queries:
            try:
                await self.execute(query)
                logger.debug("schema_query_executed", query=query[:50])
            except Exception as e:
                # Index already exists errors are okay
                if "already exists" not in str(e).lower():
                    logger.warning("schema_query_failed", query=query[:50], error=str(e))
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check Neo4j health and return stats.
        
        Returns:
            Health check results
        """
        try:
            # Get database info
            result = await self.query(
                "CALL dbms.components() YIELD name, versions, edition "
                "RETURN name, versions, edition"
            )
            db_info = result[0] if result else {}
            
            # Get node counts
            counts = await self.query(
                "MATCH (n) RETURN labels(n)[0] as label, count(n) as count "
                "ORDER BY count DESC LIMIT 10"
            )
            
            # Get relationship counts
            rel_counts = await self.query(
                "MATCH ()-[r]->() RETURN type(r) as type, count(r) as count "
                "ORDER BY count DESC LIMIT 10"
            )
            
            return {
                "status": "healthy",
                "database": db_info,
                "node_counts": {r["label"]: r["count"] for r in counts},
                "relationship_counts": {r["type"]: r["count"] for r in rel_counts},
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


class MockNeo4jConnection:
    """
    Mock Neo4j connection for testing without Neo4j.
    Stores data in memory.
    """
    
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.relationships: List[Dict[str, Any]] = []
        self._connected = False
    
    async def connect(self) -> bool:
        self._connected = True
        logger.info("mock_neo4j_connected")
        return True
    
    async def disconnect(self):
        self._connected = False
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    async def query(self, cypher: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Mock query - returns empty results."""
        return []
    
    async def execute(self, cypher: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Mock execute - simulates node/relationship creation."""
        return {
            "nodes_created": 1 if "CREATE" in cypher.upper() else 0,
            "relationships_created": 1 if "RELATIONSHIP" in cypher.upper() or "-[" in cypher else 0,
        }
    
    async def create_schema(self, schema_queries: List[str]):
        """Mock schema creation."""
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        return {
            "status": "mock",
            "node_counts": {},
            "relationship_counts": {}
        }


def get_neo4j_connection(use_mock: bool = False) -> Neo4jConnection:
    """
    Get a Neo4j connection instance.

    Args:
        use_mock: If True, return mock connection for testing

    Returns:
        Neo4j connection instance
    """
    if use_mock:
        logger.info("neo4j_mock_requested", reason="use_mock=True")
        return MockNeo4jConnection()

    if not NEO4J_AVAILABLE:
        logger.warning(
            "neo4j_unavailable_using_mock",
            reason="neo4j Python package not installed — all graph queries will return empty results. "
                   "Install with: pip install neo4j",
        )
        return MockNeo4jConnection()

    # Check if Neo4j is actually configured (not just importable)
    neo4j_uri = os.getenv("NEO4J_URI", "")
    if not neo4j_uri:
        logger.warning(
            "neo4j_not_configured_using_mock",
            reason="NEO4J_URI environment variable not set — risk scoring, association analysis, "
                   "and graph traversal will return empty results",
        )
        return MockNeo4jConnection()

    return Neo4jConnection()
