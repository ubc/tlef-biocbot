'use client'
import { useState } from 'react';
import { useEffect } from 'react';

export default function Home () {
  // empty prompt, fills it with the Set
  const [prompt, setPrompt] = useState('');
  // the rely from the LLM/Slack
  const [reply, setReply] = useState('');
  // the loading of the State
  const [loading, setLoading] = useState(false);
  const [response, setResponse ] = useState("In progess...")

  useEffect(() => {
    fetch('http://localhost:7736/api/biocbot')
      .then((response) => response.json())
      .then((data) => {
        setResponse(data.message || 'Success!');
      })
      .catch((error) => {
        console.error('Error fetching data:', error);
        setResponse('Error fetching data');
      });
  }, []);      //

  const askBot = async () => {
    if (!prompt) {
      alert('Please enter a prompt');
      return;
    }
    setLoading(true);
    setReply('');

  const res = await fetch('/api/biocbot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages:[{ role:'user', content:prompt }] })
    })
    const { result } = await res.json();
    setReply(result);

  
  await fetch('/notify/slack', {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({
        target:'#your-channel',
        body:`Q: ${prompt}\nA: ${result}`
      })
    })

    setLoading(false)
  }
  return (
    <main>
      <h1> BiocBot Status</h1>
      <p> {response} </p>
    </main>
  );
}