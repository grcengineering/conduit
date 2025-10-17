/**
 * Chat Message - Renders different message types
 */
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { Bot, User } from 'lucide-react'
import ExtractionCard from './ExtractionCard'
import ValidationCard from './ValidationCard'
import ComplianceCard from './ComplianceCard'
import ActionCard from './ActionCard'

const ChatMessage = ({ message, onAddToDashboard }) => {
  if (message.type === 'user') {
    return <UserMessage content={message.content} />
  }

  // Bot messages
  if (message.subtype === 'extraction') {
    return (
      <>
        <BotMessage content={message.content} />
        <ExtractionCard data={message.data} />
      </>
    )
  }

  if (message.subtype === 'validation') {
    return (
      <>
        <BotMessage content={message.content} />
        <ValidationCard checks={message.data.checks} />
      </>
    )
  }

  if (message.subtype === 'compliance') {
    return (
      <>
        <BotMessage content={message.content} />
        <ComplianceCard {...message.data} />
      </>
    )
  }

  if (message.subtype === 'action') {
    return (
      <>
        <BotMessage content={message.content} />
        <ActionCard data={message.data} onAddToDashboard={onAddToDashboard} />
      </>
    )
  }

  // Default bot message
  return <BotMessage content={message.content} />
}

const UserMessage = ({ content }) => {
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
      className="flex justify-end mb-4"
    >
      <div className="flex items-start gap-3 max-w-2xl">
        <Card className="p-4 bg-blue-50 border-blue-200">
          <pre className="text-sm whitespace-pre-wrap text-gray-800 font-sans">
            {content}
          </pre>
        </Card>
        <div className="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center flex-shrink-0">
          <User className="w-5 h-5 text-white" />
        </div>
      </div>
    </motion.div>
  )
}

const BotMessage = ({ content }) => {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
      className="flex justify-start mb-2"
    >
      <div className="flex items-start gap-3 max-w-2xl">
        <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center flex-shrink-0">
          <Bot className="w-5 h-5 text-gray-600" />
        </div>
        <Card className="p-3 bg-gray-50">
          <p className="text-sm text-gray-800">{content}</p>
        </Card>
      </div>
    </motion.div>
  )
}

export default ChatMessage
