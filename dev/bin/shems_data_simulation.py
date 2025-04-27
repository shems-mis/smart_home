#!/usr/bin/env python3
#!/app/dev/smarthome/bin/venv/bin/python
import os
import sys
import random
import time
from datetime import datetime, timedelta
import pymysql
from pymysql.cursors import DictCursor
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/smarthome/data/logs/shems_simulation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SHEMS-Simulator')

# Get environment variables
DB_USER = os.getenv('DB_USER', 'shems_mis')
DB_PASS = os.getenv('DB_PASS', 'RAS@23')
DB_NAME = os.getenv('DB_NAME', 'shems_db')

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=DictCursor
    )

def generate_device_name(device_type, index):
    types = {
        'Lighting': ['LED Bulb', 'Smart Light', 'Lamp', 'Ceiling Light'],
        'Appliance': ['Refrigerator', 'Washing Machine', 'Dishwasher', 'Microwave'],
        'HVAC': ['AC Unit', 'Heater', 'Fan', 'Air Purifier'],
        'Entertainment': ['TV', 'Game Console', 'Sound System', 'Streaming Box'],
        'Other': ['Smart Plug', 'Router', 'Charger', 'Unknown Device']
    }
    return f"{random.choice(types[device_type])} #{index}"

def simulate_device_data(user_id, num_devices, num_days):
    device_types = ['Lighting', 'Appliance', 'HVAC', 'Entertainment', 'Other']
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Create devices for this user
                devices = []
                for i in range(1, num_devices + 1):
                    device_type = random.choice(device_types)
                    device_name = generate_device_name(device_type, i)
                    rated_power = random.uniform(5.0, 2000.0)  # Watts
                    
                    cursor.execute("""
                        INSERT INTO DeviceInfo 
                        (UserId, DeviceName, DeviceType, SerialNumber, Manufacturer, RatedPower)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        user_id,
                        device_name,
                        device_type,
                        f"SN-{user_id}-{i}-{random.randint(1000, 9999)}",
                        random.choice(['Samsung', 'LG', 'Sony', 'Philips', 'Generic']),
                        round(rated_power, 2)
                    ))
                    device_id = cursor.lastrowid
                    devices.append({
                        'id': device_id,
                        'type': device_type,
                        'rated_power': rated_power,
                        'name': device_name
                    })
                conn.commit()
                
                logger.info(f"Created {num_devices} devices for user {user_id}")
                
                # Generate utilization data for each day
                end_time = datetime.now()
                start_time = end_time - timedelta(days=num_days)
                
                for device in devices:
                    current_time = start_time
                    last_power = 0
                    last_energy = 0
                    
                    while current_time <= end_time:
                        # Simulate usage patterns based on device type
                        if device['type'] == 'Lighting':
                            # Lights are more active in mornings and evenings
                            hour = current_time.hour
                            if 6 <= hour <= 8 or 17 <= hour <= 23:
                                status = 'ON' if random.random() > 0.3 else 'OFF'
                            else:
                                status = 'OFF' if random.random() > 0.7 else 'ON'
                        elif device['type'] == 'Appliance':
                            # Appliances have intermittent usage
                            status = 'ON' if random.random() > 0.8 else 'OFF'
                        elif device['type'] == 'HVAC':
                            # HVAC has longer cycles
                            status = 'ON' if random.random() > 0.6 else 'OFF'
                        else:
                            status = 'ON' if random.random() > 0.5 else 'OFF'
                        
                        if status == 'ON':
                            # When device is on, power consumption is 50-100% of rated power
                            power_factor = random.uniform(0.9, 1.0)
                            power = device['rated_power'] * random.uniform(0.5, 1.0)
                            current = power / (120 * power_factor)  # Assuming 120V
                            voltage = 120 * random.uniform(0.95, 1.05)
                            energy = power * 0.25 / 1000  # kWh for 15min interval
                        else:
                            # When device is off, minimal power (standby)
                            power_factor = 0
                            power = device['rated_power'] * random.uniform(0.001, 0.01)
                            current = 0
                            voltage = 0
                            energy = 0
                        
                        # Add some random fluctuations
                        power *= random.uniform(0.95, 1.05)
                        energy *= random.uniform(0.9, 1.1)
                        
                        cursor.execute("""
                            INSERT INTO DeviceUtilData
                            (DeviceId, Power_Consmpt, Energy, Voltage, Current, PowerFactor, Status, Timestamp)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            device['id'],
                            round(power, 2),
                            round(energy, 4),
                            round(voltage, 2),
                            round(current, 3),
                            round(power_factor, 2),
                            status,
                            current_time
                        ))
                        
                        # Move forward in time (15 minute intervals)
                        current_time += timedelta(minutes=15)
                    
                    logger.info(f"Generated data for device {device['id']} ({device['name']})")
                
                conn.commit()
                logger.info(f"Completed data generation for user {user_id}")
                
    except Exception as e:
        logger.error(f"Error in simulation: {str(e)}")
        raise

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: shems_data_simulation.py <user_id> <num_devices> <num_days>")
        sys.exit(1)
    
    user_id = int(sys.argv[1])
    num_devices = int(sys.argv[2])
    num_days = int(sys.argv[3])
    
    logger.info(f"Starting simulation for user {user_id} with {num_devices} devices over {num_days} days")
    simulate_device_data(user_id, num_devices, num_days)

