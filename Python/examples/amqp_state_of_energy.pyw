#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Tesla-API <https://github.com/Matthew1471/Tesla-API>
# Copyright (C) 2025 Matthew1471!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
 
# This script makes heavy use of JSON parsing.
import json

# Queue for inter-thread communication
import queue

# Both Pika and tkinter are blocking functions. 
import threading

# We use tkinter to provide a GUI.
import tkinter as tk

# Third party library; "pip install pika"
import pika

# Milliseconds
QUEUE_UPDATE_INTERVAL = 500


def callback(ch, method, properties, body):
    # Parse the JSON.
    json_object = json.loads(body)

    # Update the label text with the received number.
    message_queue.put(json_object)

def update_label():
    try:
        # Get the value from the queue.
        json_object = message_queue.get_nowait()

        label_text = f'🔋 SoC: {json_object["state_of_energy"]}%\n\n'
        label_text += f'☀️ Solar: {json_object["readings"]["solar"]["instant_power"]} W\n'
        label_text += f'🏠 Load: {json_object["readings"]["load"]["instant_power"]:.2f} W\n'
        label_text += f'🔋 Battery: {json_object["readings"]["battery"]["instant_power"]:.0f} W\n'
        label_text += f'⚡ Grid: {json_object["readings"]["site"]["instant_power"]} W'

        # Update the label with the received number
        label.config(text=label_text)
    except queue.Empty:
        # Ignore an empty queue.
        pass

    # Schedule the next update.
    root.after(QUEUE_UPDATE_INTERVAL, update_label)

def consume_messages():
    # Load credentials.
    with open('configuration/credentials.json', mode='r', encoding='utf-8') as json_file:
        credentials = json.load(json_file)

    # Gather the AMQP details from the credentials file.
    amqp_host = credentials.get('amqp_host', 'localhost')
    amqp_username = credentials.get('amqp_username', 'guest')
    amqp_password = credentials.get('amqp_password', 'guest')

    # Gather the AMQP credentials into a PlainCredentials object.
    amqp_credentials = pika.PlainCredentials(username=amqp_username, password=amqp_password)

    # The information that is visible to the broker.
    client_properties = {
        'connection_name': 'AMQP_State_Of_Energy',
        'product': 'Tesla-API',
        'version': '0.1',
        'information': 'https://github.com/Matthew1471/Tesla-API'
    }

    # Gather the AMQP connection parameters.
    amqp_parameters = pika.ConnectionParameters(
        host=amqp_host,
        credentials=amqp_credentials,
        client_properties=client_properties
    )

    # Connect to the AMQP broker.
    with pika.BlockingConnection(parameters=amqp_parameters) as amqp_connection:
            
        # Get reference to the virtual connection within AMQP.
        amqp_channel = amqp_connection.channel()

        # Declare a queue (if it does not already exist).
        amqp_result = amqp_channel.queue_declare(
            queue='Tesla_State_Of_Energy',
            durable=False,
            exclusive=True,
            auto_delete=True
        )

        # Bind the queue to the exchange (if it is not already bound).
        amqp_channel.queue_bind(
            queue=amqp_result.method.queue,
            exchange='Tesla',
            routing_key='MeterStream'
        )

        # Set up a consumer.
        amqp_channel.basic_consume(queue=amqp_result.method.queue, on_message_callback=callback, auto_ack=True)

        # Start consuming.
        amqp_channel.start_consuming()
    
def main():
    global root
    root = tk.Tk()
    root.title('Tesla® Powerwall® State Of Charge')

    # Create a label to display the number with a larger font size.
    global label
    label = tk.Label(root, text='No data received', font=('Arial', 48))
    label.pack(padx=20, pady=20, expand=True, fill=tk.BOTH)

    # Create a queue for inter-thread communication
    global message_queue
    message_queue = queue.Queue()

    # Start consuming messages in a separate thread
    consume_thread = threading.Thread(target=consume_messages)
    consume_thread.start()

    # Start updating the label in the main thread using after().
    root.after(QUEUE_UPDATE_INTERVAL, update_label)

    # Start the Tkinter main loop in a separate thread
    root.mainloop()

# Launch the main method if invoked directly.
if __name__ == '__main__':
    main()
