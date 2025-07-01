import time
from datetime import datetime, timezone, timedelta
from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func


from lib.components import db
from lib.helper_functions import ThreadedTicker
from lib.k8s.metrics import getNodeMetrics, getPodMetrics

##############################################################
## DB models
##############################################################

class Nodes(UserMixin, db.Model):
    """Table to store node metrics.

    Args:
        db (Model): SQLAlchemy database 
        
    Attributes:
        uid (text): Unique identifier for each node
        name (text): Name of the node
        cpu (text): CPU usage of the node
        memory (text): Memory usage of the node
        storage (text): Storage usage of the node
        time (datetime): Time when the data was scraped
    """
    __tablename__ = 'metrics_nodes'
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    cpu = db.Column(db.Float, nullable=False)
    memory = db.Column(db.Float, nullable=False)
    storage = db.Column(db.Float, nullable=False)
    time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<MetricsNode {self.uid}: {self.name}>"  
    
class Pods(UserMixin, db.Model):
    """Table to store pod metrics.

    Args:
        db (Model): SQLAlchemy database
        
    Attributes:
        uid (text): Unique identifier for each pod
        name (text): Name of the pod
        namespace (text): Namespace of the pod
        container (text): Name of the container
        cpu (text): CPU usage of the pod
        memory (text): Memory usage of the pod
        storage (text): Storage usage of the pod
        time (datetime): Time when the data was scraped
    """
    __tablename__ = 'metrics_pods'
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    namespace = db.Column(db.String(255), nullable=False)
    container = db.Column(db.String(255), nullable=False)
    cpu = db.Column(db.Float, nullable=False)
    memory = db.Column(db.Float, nullable=False)
    storage = db.Column(db.Float, nullable=False)
    time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<MetricsPod {self.uid}: {self.neme}>"
    
##############################################################
## Functions
##############################################################

def UpdateDatabase(app: Flask, db: SQLAlchemy, nodeMetrics, podMetrics):
    """UpdateDatabase updates nodeMetrics and podMetrics with scraped data
    
    Args:
        app (Flask): Flask app object
        db (SQLAlchemy): SQLAlchemy object
        nodeMetrics (list): Node metrics scraped from Prometheus
        podMetrics (list): Pod metrics scraped from Prometheus
    """
   
    with app.app_context():
        for node in nodeMetrics:
            node_data = Nodes(
                name=node["name"],
                cpu=node["cpu"],
                memory=node["memory"],
                storage=node["storage"],  # Assuming storage is part of node metrics
            )
            db.session.add(node_data)           
        for pod in podMetrics:
            pod_data = Pods(
                name=node["name"],
                namespace=pod["namespace"],
                container=pod["container"],
                cpu=pod["cpu"], 
                memory=pod["memory"],
                storage=pod["storage"],  # Assuming storage is part of pod metrics
            )
            db.session.add(pod_data)
        db.session.commit()
        
def CullDatabase(app: Flask, db: SQLAlchemy, window: int):
    """CullDatabase deletes rows from nodes and pods based on a time window.

    Args:
        app (Flask): Flask app object
        db (SQLAlchemy): SQLAlchemy database
        window (int): time window
    """
    
    windowStr = datetime.now() - timedelta(hours=window)
    
    with app.app_context():
        # Delete rows older than the specified window from nodes table
        db.session.query(Nodes).filter(Nodes.time < windowStr).delete()       
        # Delete rows older than the specified window from pods table
        db.session.query(Pods).filter(Pods.time < windowStr).delete()
        db.session.commit()

def update_metrics(app: Flask, db: SQLAlchemy, window: int):
    """Update the Node and Pod metrics in the provided DB

    Args:
        app (Flask): Flask app object
        db (SQLAlchemy): SQLAlchemy object
        window (int): Duration in hours to keep metrics in the DB
    """
    
    start_time = time.time()
    nodeMetrics = getNodeMetrics()
    podMetrics  = getPodMetrics()

    if nodeMetrics and podMetrics:
        UpdateDatabase(app, db, nodeMetrics, podMetrics)
        CullDatabase(app, db, window)
        app.logger.info("Scraping metrics...")
        app.logger.info(f"Metrics update took {time.time() - start_time:.2f}s")

##############################################################
## Main function
##############################################################
from functools import partial

def initialize_metrics_scraper(app: Flask):
    """Initialize the metrics scraper with a 300-second interval
    
    Args:
        app (Flask): Flask app object
    """
    ticker = ThreadedTicker(
        interval_sec=300, 
        func=partial(update_metrics, app, db, 30)
        )
    ticker.start()