import React from 'react';
import './Card.css';

function Card({ tokens }) {
  return (
    <div>
      {tokens && tokens.map((tokenInstance, index) => {
        return (
          <div key={index} className='card'>
            <p>{tokenInstance.token.ticketClass}</p>
            <p>Conference Id: {tokenInstance.token.conferenceId}</p>
            <p>Ticket Id: {tokenInstance.token.ticketId}</p>
          </div>
        )
      })}
    </div>
  );
}

export default Card;
