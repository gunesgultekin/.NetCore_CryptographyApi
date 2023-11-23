using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PUBLIC_KEY_INFRASTRUCTURE.Context;
using PUBLIC_KEY_INFRASTRUCTURE.Entities;

namespace PUBLIC_KEY_INFRASTRUCTURE.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MessagesContoller : ControllerBase
    {
        private DBContext _context;

        public MessagesContoller (DBContext context)
        {
            this._context = context;
        }

        [HttpGet("getAll")]
        public async Task<ActionResult<List<Messages>>> getAll()
        {
            List<Messages> list = await _context.Messages.ToListAsync();
            if (list.Count == 0 || list == null)
            {
                return BadRequest("No Messages found in mesaages channel");

            }
            return list;

        }
    }
}
